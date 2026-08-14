import path from "path"

process.env.OPENHACK_DB = ":memory:"
process.env.OPENHACK_MODELS_PATH = path.join(import.meta.dir, "plugin", "fixtures", "models-dev.json")
process.env.OPENHACK_DISABLE_MODELS_FETCH = "true"
