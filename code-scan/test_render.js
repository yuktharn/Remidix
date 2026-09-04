async function test() {
  // Test CORS from Vercel origin
  const res = await fetch("https://remidix-backend.onrender.com/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Origin": "https://remidix-qdeceix87-yuktharns-projects.vercel.app" },
    body: JSON.stringify({ code: 'console.log("hello");', scanMode: "quick" }),
  });
  console.log("Status:", res.status);
  const corsHeaders = {};
  res.headers.forEach((v, k) => { if (k.includes("access")) corsHeaders[k] = v; });
  console.log("CORS headers:", JSON.stringify(corsHeaders));
  const text = await res.text();
  console.log("Body:", text.substring(0, 500));
}
test();
