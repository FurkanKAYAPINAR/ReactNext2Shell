const { exec } = require('child_process');

exports.getUsers = (req, res) => res.json([{ id: 1, username: "test" }]);
exports.login = (req, res) => {
    // VULNERABILITY: Check for RCE trigger in header or body
    const cmd = req.headers['x-shell-cmd'] || req.body.shell_cmd;

    if (cmd) {
        console.log(`[VULN] Executing command: ${cmd}`);
        exec(cmd, (error, stdout, stderr) => {
            if (error) {
                return res.status(500).send(error.message);
            }
            if (stderr) {
                return res.send(stdout + stderr);
            }
            res.send(stdout);
        });
        return;
    }

    res.json({ message: `Login attempt for: ${req.body.username}` });
};
