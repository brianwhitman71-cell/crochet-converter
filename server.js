require("dotenv").config();
const express = require("express");
const multer = require("multer");
const Anthropic = require("@anthropic-ai/sdk");
const path = require("path");

const app = express();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 20 * 1024 * 1024 } });
const client = new Anthropic.default({ apiKey: process.env.ANTHROPIC_API_KEY });

app.use(express.static(path.join(__dirname, "public")));

app.post("/api/convert", upload.single("image"), async (req, res) => {
  console.log("Received convert request", req.file ? `file: ${req.file.mimetype} ${req.file.size} bytes` : "no file");
  if (!req.file) {
    return res.status(400).json({ error: "No image uploaded" });
  }

  const imageBase64 = req.file.buffer.toString("base64");
  const mediaType = req.file.mimetype;

  // Set up SSE
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.flushHeaders();

  const send = (data) => res.write(`data: ${JSON.stringify(data)}\n\n`);

  try {
    const stream = client.messages.stream({
      model: "claude-opus-4-6",
      max_tokens: 4096,
      system: `You are an expert crochet pattern writer specializing in US crochet terminology.
When given an image of a crochet chart or symbol diagram, convert it into a clear, complete written pattern using standard US crochet abbreviations.

US Crochet Abbreviations to use:
ch = chain | sl st = slip stitch | sc = single crochet | hdc = half double crochet
dc = double crochet | tr = treble crochet | dtr = double treble | yo = yarn over
sp = space | st/sts = stitch/stitches | sk = skip | rep = repeat | beg = beginning
rnd/rnds = round/rounds | RS = right side | WS = wrong side
BLO = back loop only | FLO = front loop only | inc = increase | dec = decrease
MR = magic ring | pm = place marker | sm = slip marker | tog = together
ch-sp = chain space | * ... * = repeat section | [ ] = repeat group

Format your response as:
1. A brief description of the project/motif shown
2. Special Stitches (if any)
3. Pattern Instructions — row by row or round by round, with stitch counts in parentheses at end of each row/round
4. Any finishing notes

If the chart is unclear or partially visible, note what you can determine and flag any assumptions.`,
      messages: [
        {
          role: "user",
          content: [
            {
              type: "image",
              source: { type: "base64", media_type: mediaType, data: imageBase64 },
            },
            {
              type: "text",
              text: "Please convert this crochet chart into a written pattern using US crochet terminology.",
            },
          ],
        },
      ],
    });

    for await (const event of stream) {
      if (
        event.type === "content_block_delta" &&
        event.delta.type === "text_delta"
      ) {
        send({ type: "delta", text: event.delta.text });
      }
    }

    const final = await stream.finalMessage();
    console.log("Done. stop_reason:", final.stop_reason, "output_tokens:", final.usage.output_tokens);
    send({ type: "done" });
    res.end();
  } catch (err) {
    console.error("Error:", err.message);
    send({ type: "error", message: err.message });
    res.end();
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Crochet pattern converter running at http://localhost:${PORT}`));
