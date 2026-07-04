const { execFile } = require('child_process');

function run() {
  execFile('ls', ['-l']);                  // safe
}
