import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Build "standalone": Next produce un servidor mínimo autocontenido (.next/standalone)
  // con solo las dependencias usadas, para una imagen Docker pequeña en el self-host (H5-T43).
  output: "standalone",
};

export default nextConfig;
