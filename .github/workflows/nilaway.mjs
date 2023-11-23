import { promises as fs } from 'node:fs';
import path from 'node:path';

if (process.argv.length < 3) {
  throw new Error(`Usage: ${process.execPath} ${process.execArgv.join(' ')} ${process.argv[1]} <json-report-path>`);
}

const jsonReportPath = process.argv[2];

const text = await fs.readFile(jsonReportPath, 'utf-8');
const json = JSON.parse(text);

for (const { nilaway } of Object.values(json)) {
  for (const { posn, message } of nilaway) {
    annotate(posn, message);
  }
}

function annotate(pos, message) {
  const [file, line, col] = pos.split(':', 3);
  const relative = path.relative(process.cwd(), file);
  console.log(`::warning file=${relative},line=${line},col=${col},title=NilAway::${escapeSpecial(message)}`);
}

function escapeSpecial(text) {
  return text.replace(/%/g, '%25')
    .replace(/\r/g, '%0D')
    .replace(/\n/g, '%0A');
}
