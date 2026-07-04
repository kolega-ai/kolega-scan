const child_process = require('child_process');

function run(req) {
  child_process.exec('rm ' + req.query.f);
}
