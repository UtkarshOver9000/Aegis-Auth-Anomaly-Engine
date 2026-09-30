# System Architecture

The Impossible-Travel Auth Anomaly Engine is designed for high-throughput, low-latency authentication evaluation.

## Components

1. **API Gateway (FastAPI)**: Handles incoming POST requests. Authenticates clients using `X-API-Key`.
2. **State Store (StateStore)**: Maintains an in-memory (or Redis-backed) history of the last known location, IP, and device for every user.
3. **ML Engine (IsolationForest)**: A pre-trained unsupervised model evaluating features like distance, velocity, device novelty, and IP subnet jumps.
4. **Geo Physics Engine (Haversine)**: Calculates the great-circle distance between coordinates on a sphere (Earth).

## Future Scalability
For production, the in-memory state store should be replaced with Redis for distributed scaling across multiple Kubernetes pods.
