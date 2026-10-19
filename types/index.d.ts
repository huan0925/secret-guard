declare module 'claude-code' {
  interface PluginState {
    'secret-guard': { sessionAllowed: string[] }
  }
}
