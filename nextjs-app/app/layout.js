export const metadata = {
  title: "Next.js Test App",
  description: "Vuln PoC Next.js",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
