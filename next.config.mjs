/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: false, // Prevents double-mount GSAP/Three scene teardowns in dev
  transpilePackages: ['three'],
};

export default nextConfig;

