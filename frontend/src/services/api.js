import axios from "axios";
import { API_BASE } from "../config";

export default axios.create({
  baseURL: API_BASE,
});
