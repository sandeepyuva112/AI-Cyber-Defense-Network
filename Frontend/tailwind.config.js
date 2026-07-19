/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyberBg: "#070B14",
        cyberSurface: "#101827",
        cyberPrimary: "#00E5FF",
        cyberPurple: "#8B5CF6",
        cyberSuccess: "#22C55E",
        cyberWarning: "#FACC15",
        cyberDanger: "#EF4444",
      },
      fontFamily: {
        cyber: ["Outfit", "Inter", "sans-serif"],
      },
      boxShadow: {
        glow: "0 0 15px rgba(0, 229, 255, 0.4)",
        purpleGlow: "0 0 15px rgba(139, 92, 246, 0.4)",
        redGlow: "0 0 15px rgba(239, 68, 68, 0.4)",
      }
    },
  },
  plugins: [],
}
