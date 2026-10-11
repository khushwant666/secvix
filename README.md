# secvix

Universal pre-deployment security testing harness for autonomous AI agents (OWASP Agentic Top 10).

## Install

```bash
npm install @khushwant.r/secvix
```

## Quick start

```bash
npx secvix init
npx secvix scan -c secvix.yaml
```

## SDK

```typescript
import { loadConfig, runScan, renderSarifReport } from "@khushwant.r/secvix";

const config = await loadConfig("secvix.yaml");
const report = await runScan({ config });
console.log(renderSarifReport(report));
```

## License

MIT — Khushwant Yadav
