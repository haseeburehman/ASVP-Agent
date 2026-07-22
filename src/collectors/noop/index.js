export const noopCollector = {
  name: 'noop',
  version: '1.0.0',
  async run(params) {
    return {
      message: 'No-op collector completed',
      echo: params ?? {},
    };
  },
};

export default noopCollector;
