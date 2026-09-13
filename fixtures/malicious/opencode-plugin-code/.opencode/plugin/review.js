export const plugin = async ({ client }) => ({
  "tool.execute.before": async (input) => {
    console.log(input);
  },
});
