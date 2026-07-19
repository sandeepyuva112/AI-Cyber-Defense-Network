const { spawn, execSync } = require("child_process");
const path = require("path");
const http = require("http");

console.log("=== AI CYBER DEFENSE NETWORK STARTUP ORCHESTRATOR ===");

let backendProcess = null;

function checkBackendActive() {
  return new Promise((resolve) => {
    http.get("http://127.0.0.1:8000/api/v1/health-checks", (res) => {
      resolve(res.statusCode === 200);
    }).on("error", () => {
      resolve(false);
    });
  });
}

async function start() {
  const isAlreadyRunning = await checkBackendActive();
  
  if (isAlreadyRunning) {
    console.log("Python backend is already running on port 8000. Skipping launch.");
  } else {
    const backendPath = path.join(__dirname, "..", "Backend");
    console.log(`Starting Python backend in ${backendPath}...`);

    let pythonCmd = "python";
    try {
      execSync("python --version", { stdio: "ignore" });
    } catch (e) {
      pythonCmd = "python3";
    }

    backendProcess = spawn(pythonCmd, ["-m", "uvicorn", "app.main:create_app", "--host", "127.0.0.1", "--port", "8000"], {
      cwd: backendPath,
      stdio: "inherit",
      shell: true
    });

    backendProcess.on("error", (err) => {
      console.error("Failed to start Python backend process:", err);
      process.exit(1);
    });

    // Wait for it to become healthy
    console.log("Waiting for backend API to initialize...");
    let healthy = false;
    for (let attempt = 1; attempt <= 15; attempt++) {
      await new Promise(r => setTimeout(r, 1000));
      healthy = await checkBackendActive();
      if (healthy) {
        console.log("Backend API is healthy and reachable.");
        break;
      }
      console.log(`Checking backend API health (Attempt ${attempt}/15)...`);
    }

    if (!healthy) {
      console.error("Backend API failed to start in time.");
      if (backendProcess) backendProcess.kill();
      process.exit(1);
    }
  }

  console.log("Booting Electron desktop shell...");
  const isDev = process.argv.includes("--dev");
  const args = isDev ? ["main.cjs", "--dev"] : ["main.cjs"];
  
  const electronProcess = spawn("npx", ["electron", ...args], {
    cwd: __dirname,
    stdio: "inherit",
    shell: true
  });

  electronProcess.on("close", (code) => {
    console.log(`Electron closed with code ${code}.`);
    if (backendProcess) {
      console.log("Terminating Python backend process...");
      backendProcess.kill();
    }
    process.exit(code);
  });
}

start();

// Handle termination signals
process.on("SIGINT", () => {
  console.log("Interrupt received. Clean quit...");
  if (backendProcess) backendProcess.kill();
  process.exit(0);
});
process.on("SIGTERM", () => {
  console.log("Termination received. Clean quit...");
  if (backendProcess) backendProcess.kill();
  process.exit(0);
});
