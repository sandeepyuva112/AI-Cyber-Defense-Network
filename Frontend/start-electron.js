const { spawn, execSync } = require("child_process");
const path = require("path");
const http = require("http");

console.log("=== AI CYBER DEFENSE NETWORK STARTUP ORCHESTRATOR ===");

// 1. Start Python Backend
const backendPath = path.join(__dirname, "..", "Backend");
console.log(`Starting Python backend in ${backendPath}...`);

// Use python or python3 depending on system
let pythonCmd = "python";
try {
  execSync("python --version", { stdio: "ignore" });
} catch (e) {
  pythonCmd = "python3";
}

const backendProcess = spawn(pythonCmd, ["-m", "uvicorn", "app.main:create_app", "--host", "127.0.0.1", "--port", "8000"], {
  cwd: backendPath,
  stdio: "inherit", // Pipe output to parent console
  shell: true
});

backendProcess.on("error", (err) => {
  console.error("Failed to start Python backend process:", err);
  process.exit(1);
});

// 2. Poll Backend Health
function checkBackendHealth(retries = 10, delay = 1000) {
  return new Promise((resolve, reject) => {
    const attempt = (n) => {
      console.log(`Checking backend API health (Attempt ${11 - n}/10)...`);
      http.get("http://127.0.0.1:8000/api/v1/settings/health", (res) => {
        if (res.statusCode === 200) {
          console.log("Backend API is healthy and reachable.");
          resolve();
        } else {
          fallback(n);
        }
      }).on("error", () => {
        fallback(n);
      });
    };

    const fallback = (n) => {
      if (n <= 1) {
        reject(new Error("Backend API failed to start in time."));
      } else {
        setTimeout(() => attempt(n - 1), delay);
      }
    };

    attempt(retries);
  });
}

// 3. Start Electron once API is up
checkBackendHealth()
  .then(() => {
    console.log("Booting Electron desktop shell...");
    const isDev = process.argv.includes("--dev");
    const args = isDev ? ["main.js", "--dev"] : ["main.js"];
    
    const electronProcess = spawn("npx", ["electron", ...args], {
      cwd: __dirname,
      stdio: "inherit",
      shell: true
    });

    electronProcess.on("close", (code) => {
      console.log(`Electron closed with code ${code}. Terminating backend process...`);
      backendProcess.kill();
      process.exit(code);
    });
  })
  .catch((err) => {
    console.error(err.message);
    backendProcess.kill();
    process.exit(1);
  });

// Handle termination signals to cleanly shut down python backend
process.on("SIGINT", () => {
  console.log("Interrupt received. Killing backend...");
  backendProcess.kill();
  process.exit(0);
});
process.on("SIGTERM", () => {
  console.log("Termination received. Killing backend...");
  backendProcess.kill();
  process.exit(0);
});
