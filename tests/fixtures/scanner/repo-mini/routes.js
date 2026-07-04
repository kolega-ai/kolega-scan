const child_process = require('child_process');
const password = "hunter2-long-enough";   // hardcoded secret

function run(req) {
  child_process.exec('rm ' + req.query.f); // command injection
}
