const { app, BrowserWindow } = require("electron");
const path = require("path");

let mainWindow;

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 800,
    minWidth: 1024,
    minHeight: 768,
    frame: true, // Show standard titlebars
    title: "AI Cyber Defense Network SOC Console",
    backgroundColor: "#070B14",
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, "preload.js")
    }
  });

  // Hide default top menu bar
  mainWindow.setMenuBarVisibility(false);

  // Check if dev server is requested
  const isDev = process.env.NODE_ENV === "development" || process.argv.includes("--dev");
  if (isDev) {
    mainWindow.loadURL("http://127.0.0.1:5173");
    // Open devtools in development
    mainWindow.webContents.openDevTools();
  } else {
    mainWindow.loadFile(path.join(__dirname, "dist", "index.html"));
  }

  mainWindow.on("closed", () => {
    mainWindow = null;
  });
}

app.whenReady().then(() => {
  createWindow();

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    app.quit();
  }
});
