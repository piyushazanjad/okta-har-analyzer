import 'dotenv/config';
import express from 'express';
import Anthropic from '@anthropic-ai/sdk';
import { fileURLToPath } from 'url';
import path from 'path';
import { parseHAR, buildClaudePrompt } from './harParser.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const client = new Anthropic();

app.use(express.json({ limit: '200mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ─── Parse HAR ────────────────────────────────────────────────────────────
app.post('/api/analyze', (req, res) => {
  try {
    const har = req.body;
    if (!har?.log?.entries) {
      return res.status(400).json({ error: 'Invalid HAR format — missing log.entries' });
    }
    const flowData = parseHAR(har);
    if (flowData.error) {
      return res.status(400).json({ error: flowData.error });
    }
    res.json(flowData);
  } catch (err) {
    console.error('Parse error:', err.message);
    res.status(500).json({ error: `Failed to parse HAR: ${err.message}` });
  }
});

// ─── Stream Claude Verdict ─────────────────────────────────────────────────
app.post('/api/verdict', async (req, res) => {
  const flowData = req.body;

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('Access-Control-Allow-Origin', '*');

  try {
    const prompt = buildClaudePrompt(flowData);
    const stream = client.messages.stream({
      model: 'claude-4-6-opus',
      max_tokens: 2048,
      messages: [{ role: 'user', content: prompt }],
    });

    for await (const event of stream) {
      if (event.type === 'content_block_delta' && event.delta.type === 'text_delta') {
        res.write(`data: ${JSON.stringify({ text: event.delta.text })}\n\n`);
      }
    }

    res.write('data: [DONE]\n\n');
    res.end();
  } catch (err) {
    console.error('Claude API error:', err.message);
    res.write(`data: ${JSON.stringify({ error: err.message })}\n\n`);
    res.end();
  }
});

// ─── Stream Claude Chat ────────────────────────────────────────────────────
app.post('/api/chat', async (req, res) => {
  const { flowData, messages } = req.body;

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('Access-Control-Allow-Origin', '*');

  try {
    const domainContext = flowData.customOktaDomain && flowData.defaultOktaDomain
      ? `custom domain ${flowData.customOktaDomain} AND default domain ${flowData.defaultOktaDomain} (domain switch detected)`
      : flowData.oktaDomain;
    const domainSwitchContext = flowData.domainSwitchWarnings?.length
      ? ` Domain switch warnings: ${flowData.domainSwitchWarnings.map(w => w.message).join('; ')}.`
      : '';
    const stepsContext = flowData.steps.map((s, i) =>
      `Step ${i + 1}: ${s.method} ${s.url} → HTTP ${s.status}${s.locationHeader ? ` → ${s.locationHeader}` : ''}${s.keyParams ? ` [${Object.entries(s.keyParams).map(([k,v]) => `${k}=${v}`).join(',')}]` : ''}`
    ).join('\n');
    const systemContext = `You are analyzing an Okta auth flow: ${flowData.protocol} on ${domainContext}, ${flowData.totalSteps} steps, ${flowData.hasErrors ? flowData.errorCount + ' errors' : 'no errors'}.${domainSwitchContext} Answer follow-up questions concisely and technically.\n\nFull step-by-step URL trace:\n${stepsContext}`;
    const allMessages = [
      { role: 'user', content: systemContext },
      { role: 'assistant', content: 'Understood. Ask me anything about this auth flow.' },
      ...messages,
    ];

    const stream = client.messages.stream({
      model: 'claude-4-6-opus',
      max_tokens: 1024,
      messages: allMessages,
    });

    for await (const event of stream) {
      if (event.type === 'content_block_delta' && event.delta.type === 'text_delta') {
        res.write(`data: ${JSON.stringify({ text: event.delta.text })}\n\n`);
      }
    }

    res.write('data: [DONE]\n\n');
    res.end();
  } catch (err) {
    console.error('Chat API error:', err.message);
    res.write(`data: ${JSON.stringify({ error: err.message })}\n\n`);
    res.end();
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`\n  HARlens → http://localhost:${PORT}\n`);
});
