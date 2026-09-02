/** @type {import('next').NextConfig} */
const nextConfig = {
  output: process.env.NEXT_EXPORT === '0' ? undefined : 'export',
  trailingSlash: true,
}

export default nextConfig
