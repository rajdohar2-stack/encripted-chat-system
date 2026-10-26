const localHostnames = new Set(["localhost", "127.0.0.1", "::1"]);
const isLocalFrontend = localHostnames.has(window.location.hostname);

// Local previews use the local HTTPS API; deployed sites use the Render API.
window.COMMONROOM_API_URL = isLocalFrontend
    ? `https://${window.location.hostname}:5000/`
    : "https://encripted-chat-system.onrender.com/";
window.COMMONROOM_API_IS_LOCAL = isLocalFrontend;
