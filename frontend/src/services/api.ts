import axios from "axios";

export const api = axios.create({ baseURL: "http://127.0.0.1:8001/api/v1" });

export async function uploadIpa(file: File) {
  const form = new FormData();
  form.append("file", file);
  return (await api.post("/scans/upload", form)).data;
}

export async function startScan(id: string) {
  return (await api.post(`/scans/${id}/start`)).data;
}

export async function getStatus(id: string) {
  return (await api.get(`/scans/${id}`)).data;
}

export async function listScans(): Promise<any[]> {
  const res = await api.get("/scans");
  const data = res.data;
  return Array.isArray(data) ? data : [];
}

export async function getFindings(id: string): Promise<any[]> {
  const res = await api.get(`/scans/${id}/findings`);
  const data = res.data;
  return Array.isArray(data) ? data : [];
}

export async function getApplication(id: string) {
  return (await api.get(`/scans/${id}/application`)).data;
}

export async function getBinary(id: string) {
  return (await api.get(`/scans/${id}/binary`)).data;
}
