// Edge Function for /api/convert — supports true SSE streaming, no timeout.
// Uses Web Fetch API directly (no Node SDK needed).

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i += 8192) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 8192));
  }
  return btoa(binary);
}

const SYSTEM_PROMPT = `You are an expert crochet pattern reverse-engineer and pattern writer specializing in US crochet terminology.
You accept two types of images and handle each accordingly:

TYPE A — Crochet chart / symbol diagram: Convert the symbols directly into a written pattern.
TYPE B — Photo of a finished crochet project (amigurumi, garment, accessory, blanket, etc.): Carefully study the texture, stitch structure, shape, and construction visible in the photo and write a complete pattern that would reproduce it.

For TYPE B photos: examine stitch height, loop placement, increases/decreases shaping, seams, color changes, and any visible construction details. Make your best assessment of yarn weight (fingering/sport/DK/worsted/bulky) and hook size based on stitch density and scale. State your assumptions clearly but keep it fun.

US Crochet Abbreviations to use:
ch = chain | sl st = slip stitch | sc = single crochet | hdc = half double crochet
dc = double crochet | tr = treble crochet | dtr = double treble | yo = yarn over
sp = space | st/sts = stitch/stitches | sk = skip | rep = repeat | beg = beginning
rnd/rnds = round/rounds | RS = right side | WS = wrong side
BLO = back loop only | FLO = front loop only | inc = increase | dec = decrease
MR = magic ring | pm = place marker | sm = slip marker | tog = together
ch-sp = chain space | * ... * = repeat section | [ ] = repeat group
inv dec = invisible decrease | sc2tog = single crochet 2 together

Format your response as:
## Description
A brief, slightly witty description of the project — give it personality! Describe what it is, what it's for, and poke a little fun at the complexity or charm. Keep it warm and fun, not mean.

## Materials
- Yarn: estimated weight and fiber suggestion
- Hook: estimated size (US and mm)
- Other: stuffing, safety eyes, stitch markers, tapestry needle, etc. as needed

## Special Stitches
List any non-standard stitches used, with definitions. Omit this section if none.

## Pattern Instructions
Row by row or round by round. Include stitch counts in parentheses at the end of each row/round. For amigurumi and 3D pieces, work in continuous rounds unless noted. For garments or flat pieces, specify turning chains.

## Finishing Notes
Assembly instructions if applicable, plus a short encouraging or humorous remark — like a coach who also crochets. Celebrate the crafter. You may lightly roast the pattern if it's particularly fiddly.

If the image is unclear or a detail is ambiguous, note your best guess and flag it — feel free to be a little dramatic, like a detective piecing together clues.`;

export default async (request, context) => {
  if (request.method !== "POST") {
    return new Response(JSON.stringify({ error: "Method not allowed" }), {
      status: 405,
      headers: { "Content-Type": "application/json" },
    });
  }

  // Parse multipart form data
  let imageBase64, mediaType;
  try {
    const formData = await request.formData();
    const imageFile = formData.get("image");
    if (!imageFile || typeof imageFile === "string") {
      return new Response(JSON.stringify({ error: "No image uploaded" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }
    const arrayBuffer = await imageFile.arrayBuffer();
    imageBase64 = arrayBufferToBase64(arrayBuffer);
    mediaType = imageFile.type;
  } catch (err) {
    return new Response(JSON.stringify({ error: "Failed to read image" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  const apiKey = Netlify.env.get("ANTHROPIC_API_KEY");
  if (!apiKey) {
    return new Response(JSON.stringify({ error: "API key not configured" }), {
      status: 503,
      headers: { "Content-Type": "application/json" },
    });
  }

  // Set up a TransformStream to pipe Claude's stream back to the client
  const { readable, writable } = new TransformStream();
  const writer = writable.getWriter();
  const encoder = new TextEncoder();
  const send = (data) => writer.write(encoder.encode(`data: ${JSON.stringify(data)}\n\n`));

  // Run the Anthropic call in the background — the Response streams as it writes
  (async () => {
    try {
      const anthropicRes = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-api-key": apiKey,
          "anthropic-version": "2023-06-01",
        },
        body: JSON.stringify({
          model: "claude-opus-4-6",
          max_tokens: 4096,
          stream: true,
          system: SYSTEM_PROMPT,
          messages: [{
            role: "user",
            content: [
              { type: "image", source: { type: "base64", media_type: mediaType, data: imageBase64 } },
              { type: "text", text: "Please analyze this image and write a complete crochet pattern in US crochet terminology that would reproduce what you see. It may be a crochet chart/diagram OR a photo of a finished crochet project — handle whichever it is." },
            ],
          }],
        }),
      });

      if (!anthropicRes.ok) {
        const errText = await anthropicRes.text();
        await send({ type: "error", message: `Anthropic API error: ${errText}` });
        return;
      }

      const reader = anthropicRes.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop() ?? "";

        for (const line of lines) {
          if (!line.startsWith("data: ")) continue;
          const data = line.slice(6).trim();
          if (data === "[DONE]") continue;
          try {
            const parsed = JSON.parse(data);
            if (parsed.type === "content_block_delta" && parsed.delta?.type === "text_delta") {
              await send({ type: "delta", text: parsed.delta.text });
            }
          } catch (_) { /* skip unparseable lines */ }
        }
      }

      await send({ type: "done" });
    } catch (err) {
      await send({ type: "error", message: err.message });
    } finally {
      await writer.close();
    }
  })();

  return new Response(readable, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
    },
  });
};

export const config = { path: "/api/convert" };
