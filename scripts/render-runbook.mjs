/** Render the trusted, local runbook to offline HTML; never contacts live services.
 * Requires Node.js 20+ and marked. Optional RUNBOOK_MARKED_MODULE points to an
 * existing marked CommonJS installation. Run from this directory or any cwd.
 */
import { readFile, writeFile, readdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.url);
let marked;
try {
  ({ marked } = require(process.env.RUNBOOK_MARKED_MODULE || 'marked'));
} catch {
  console.error('Missing marked. Install marked in your documentation build environment, or set RUNBOOK_MARKED_MODULE to its installed module path.');
  process.exit(2);
}
const documents = (await Promise.all(['.', 'docs'].map(async directory =>
  (await readdir(path.join(root, directory))).filter(name => name.endsWith('.md'))
    .map(name => path.join(directory, name))))).flat().sort();
const sources = new Set(documents.map(name => path.join(root, name)));
for (const relative of documents) {
const source = path.join(root, relative);
const documentName = path.basename(relative, '.md');
const markdown = await readFile(source, 'utf8');
const hash = createHash('sha256').update(markdown).digest('hex');
const toc = [];
let n = 0;
let body = marked.parse(markdown, { gfm: true, breaks: false });
// Convert only known local Markdown links; external URLs and source links stay intact.
body = body.replace(/href="([^"]+)"/g, (attribute, href) => {
  if (/^(?:[a-z]+:|\/|#)/i.test(href)) return attribute;
  const [target, fragment] = href.split('#');
  const resolved = path.resolve(path.dirname(source), decodeURIComponent(target));
  if (!sources.has(resolved)) return attribute;
  return `href="${target.replace(/\.md$/, '.html')}${fragment ? '#' + fragment : ''}"`;
});
body = body.replace(/<h([123])(?:\s[^>]*)?>([\s\S]*?)<\/h\1>/g, (_, level, text) => {
  const id = `section-${++n}`;
  if (level !== '1') toc.push(`<a class="level-${level}" href="#${id}">${text}</a>`);
  return `<h${level} id="${id}">${text}</h${level}>`;
}).replace(/<table>/g, '<div class="table-scroll"><table>')
  .replace(/<\/table>/g, '</table></div>')
  .replace(/<img src="([^"]+)" alt="([^"]*)"[^>]*>/g,
    (_, src, alt) => `<a class="image-link" href="${src}" title="打开原图"><img src="${src}" alt="${alt}" loading="eager"></a>`);

const html = `<!doctype html>
<!-- source-sha256:${hash} -->
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="企业微信扫码登录 Amazon Quick：自动部署与完整手动配置图文说明。">
<title>企业微信 × Amazon Quick · ${documentName}</title>
<style>
:root{color-scheme:light;--ink:#16283f;--muted:#556579;--accent:#155c9e;--line:#dce4ec}
*{box-sizing:border-box}html{scroll-behavior:smooth;scroll-padding-top:24px}
body{margin:0;background:#f3f6fa;color:var(--ink);font:16px/1.8 -apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",sans-serif}
nav{position:fixed;inset:0 auto 0 0;width:286px;padding:24px 18px;overflow-y:auto;background:#10253f;color:#dfeaf7}
nav .brand{font-size:19px;font-weight:750;line-height:1.5;margin-bottom:12px}nav .meta{font-size:12px;color:#acc2d9;margin-bottom:22px}
nav a{display:block;color:#dfeaf7;text-decoration:none;line-height:1.5;padding:7px 9px;border-radius:5px;font-size:13px}nav a:hover{background:#234361}nav .level-2{font-weight:700;margin-top:8px}nav .level-3{padding-left:21px;color:#b8cde1}
main{margin-left:286px;padding:40px 44px 88px;max-width:1450px;min-width:0}
article{background:#fff;padding:40px 42px;border:1px solid var(--line);border-radius:14px;box-shadow:0 5px 24px #17395408;min-width:0;overflow-wrap:anywhere}
.eyebrow{color:var(--accent);font-size:12px;font-weight:750;letter-spacing:1.6px;margin-bottom:12px}
h1{font-size:30px;line-height:1.4;margin:0 0 14px;letter-spacing:-.6px}h2{font-size:24px;line-height:1.5;margin:56px 0 20px;padding-top:22px;border-top:2px solid var(--line)}h3{font-size:19px;line-height:1.5;margin:34px 0 12px;color:#155c9e}
p{margin:12px 0}li{margin:8px 0}a{color:#135c9c;text-underline-offset:3px}strong{font-weight:720}
.table-scroll{overflow-x:auto;margin:18px 0;border:1px solid var(--line);border-radius:8px}table{border-collapse:collapse;width:100%;font-size:14px;line-height:1.65}th{background:#edf3fa;color:#173954;text-align:left;font-weight:700}td,th{padding:11px 13px;border-bottom:1px solid var(--line);vertical-align:top;min-width:105px}tr:last-child td{border-bottom:0}tr:nth-child(even) td{background:#fafbfd}
code{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:.86em;background:#edf2f7;padding:2px 5px;border-radius:4px;overflow-wrap:anywhere}pre{background:#10253f;color:#e6eff7;padding:19px 21px;border-radius:8px;overflow:auto;line-height:1.65}pre code{background:none;padding:0;color:inherit;white-space:pre;font-size:13px}
img{display:block;max-width:100%;height:auto;border:1px solid var(--line);border-radius:7px;background:white}.image-link{display:block;margin:20px 0 12px;cursor:zoom-in}.image-link:hover img{border-color:#4188c4}
blockquote{margin:18px 0;padding:6px 18px;border-left:4px solid #ca8a22;background:#fff9ea}footer{margin-top:32px;color:var(--muted);font-size:12px}
@media(max-width:1050px){nav{width:235px}main{margin-left:235px;padding:24px}article{padding:26px}}
@media(max-width:760px){nav{position:relative;width:auto;max-height:340px}main{margin:0;padding:15px}article{padding:20px}h1{font-size:25px}h2{font-size:22px}body{font-size:15px}}
@media print{@page{size:A4;margin:14mm}nav,.eyebrow{display:none}body{background:white;font-size:10pt}main{margin:0;padding:0;max-width:none}article{padding:0;border:0;box-shadow:none}h1{font-size:22pt}h2{font-size:16pt;break-before:page;margin-top:0}h3{font-size:12pt;break-after:avoid}.table-scroll{overflow:visible;border:0}table{font-size:8pt}td,th{min-width:0;padding:6px}pre{white-space:pre-wrap}pre code{white-space:pre-wrap;font-size:8pt}img{max-height:220mm;width:auto;max-width:100%;break-inside:avoid}a{color:inherit}tr{break-inside:avoid}}
</style></head><body>
<nav aria-label="章节目录"><div class="brand">企业微信 × Amazon Quick<br>${documentName}</div><div class="meta">客户扫码登录实施 · 离线图文<br><a href="${relative.startsWith('docs/') ? '../' : ''}README.html">返回实施入口</a></div>${toc.join('\n')}</nav>
<main><article><div class="eyebrow">CUSTOMER IMPLEMENTATION RUNBOOK</div>${body}<footer>离线文档 · 图片为本地资源 · 点击截图查看原图 · 未实拍页面已在正文标明 · 不能代替客户验收</footer></article></main>
</body></html>`;
await writeFile(source.replace(/\.md$/, '.html'), html, 'utf8');
console.log(`Rendered ${relative}: ${toc.length} section links, ${(body.match(/<img /g)||[]).length} local images.`);
}
