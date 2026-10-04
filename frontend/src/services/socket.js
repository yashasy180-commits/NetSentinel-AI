import { io } from "socket.io-client";
import { SOCKET_URL } from "../config";

let socket = null;

export function connectSocket() {
  if (socket?.connected) {
    return socket;
  }

  socket = io(SOCKET_URL, {
    transports: ["websocket", "polling"],
    reconnection: true,
    reconnectionAttempts: 10,
    reconnectionDelay: 1000,
  });

  socket.on("connect", () => {
    console.log("[Socket.IO] Connected:", socket.id);
  });

  socket.on("disconnect", (reason) => {
    console.log("[Socket.IO] Disconnected:", reason);
  });

  socket.on("connect_error", (error) => {
    console.error("[Socket.IO] Connection error:", error.message);
  });

  return socket;
}

export function getSocket() {
  return socket;
}

export function disconnectSocket() {
  if (socket) {
    socket.disconnect();
    socket = null;
  }
}

export default {
  connectSocket,
  getSocket,
  disconnectSocket,
};
