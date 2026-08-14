const stage = process.env.SST_STAGE || "dev"

export default {
  url: stage === "production" ? "https://cybersec.org.za" : `https://cybersec.org.za`,
  console: stage === "production" ? "https://cybersec.org.za/auth" : `https://cybersec.org.za/auth`,
  email: "help@anoma.ly",
  socialCard: "https://social-cards.sst.dev",
  github: "https://github.com/anomalyco/openhack",
  discord: "https://cybersec.org.za/discord",
  headerLinks: [
    { name: "app.header.home", url: "/" },
    { name: "app.header.docs", url: "/docs/" },
  ],
}
