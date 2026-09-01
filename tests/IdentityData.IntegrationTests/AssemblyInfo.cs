using Xunit;

// Run all integration tests sequentially within this assembly.
// This prevents Serilog's static Log.Logger from being frozen by two factories concurrently.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
