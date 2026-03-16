/** @type {import('next').NextConfig} */
const nextConfig = {
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: "https://primust-api.fly.dev/api/:path*",
      },
    ];
  },
};

module.exports = nextConfig;
