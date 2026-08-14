// @ts-nocheck

import { OpenHack } from "@openhack-ai/core"
import { ReadTool } from "@openhack-ai/core/tools"

const openhack = OpenHack.make({})

openhack.tool.add(ReadTool)

openhack.tool.add({
  name: "bash",
  schema: {
    type: "object",
    properties: {
      command: {
        type: "string",
        description: "The command to run.",
      },
    },
    required: ["command"],
  },
  execute(input, ctx) {},
})

openhack.auth.add({
  provider: "openai",
  type: "api",
  value: process.env.OPENAI_API_KEY,
})

openhack.agent.add({
  name: "build",
  permissions: [],
  model: {
    id: "gpt-5-5",
    provider: "openai",
    variant: "xhigh",
  },
})

const sessionID = await openhack.session.create({
  agent: "build",
})

openhack.subscribe((event) => {
  console.log(event)
})

await openhack.session.prompt({
  sessionID,
  text: "hey what is up",
})

await openhack.session.prompt({
  sessionID,
  text: "what is up with this",
  files: [
    {
      mime: "image/png",
      uri: "data:image/png;base64,xxxx",
    },
  ],
})

await openhack.session.wait()

console.log(await openhack.session.messages(sessionID))
