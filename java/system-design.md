# System Design Key Aspects with Java Examples

## Table of Contents
1. [Scalability](#scalability)
2. [Load Balancing](#load-balancing)
3. [Caching](#caching)
4. [Database Design](#database-design)
5. [Messaging and Queues](#messaging-and-queues)
6. [Security](#security)
7. [Monitoring and Observability](#monitoring-and-observability)
8. [Fault Tolerance](#fault-tolerance)
9. [API Design](#api-design)

---

## Scalability

### Horizontal Scaling
Distributing load across multiple instances to handle increased traffic.

```java
@RestController
public class UserController {
    @Autowired
    private UserService userService;
    
    @GetMapping("/users/{id}")
    public ResponseEntity<User> getUser(@PathVariable Long id) {
        // Stateless design allows multiple instances
        User user = userService.findById(id);
        return ResponseEntity.ok(user);
    }
}
```

### Vertical Scaling
Optimizing resource usage within a single instance.

```java
@Service
public class UserService {
    @Async
    public CompletableFuture<User> processUserAsync(Long userId) {
        // Non-blocking operations for better resource utilization
        return CompletableFuture.supplyAsync(() -> {
            return userRepository.findById(userId);
        });
    }
}
```

---

## Load Balancing

### Round-Robin Distribution
Distributing requests evenly across available servers.

```java
@Component
public class LoadBalancer {
    private List<String> servers = Arrays.asList(
        "server1:8080", "server2:8080", "server3:8080"
    );
    private AtomicInteger counter = new AtomicInteger(0);
    
    public String getNextServer() {
        int index = counter.getAndIncrement() % servers.size();
        return servers.get(index);
    }
}
```

---

## Caching

### Redis Integration
Implementing distributed caching for improved performance.

```java
@Service
public class ProductService {
    @Autowired
    private RedisTemplate<String, Object> redisTemplate;
    
    @Cacheable(value = "products", key = "#id")
    public Product getProduct(Long id) {
        // Cache miss will hit database
        return productRepository.findById(id);
    }
    
    @CacheEvict(value = "products", key = "#product.id")
    public Product updateProduct(Product product) {
        return productRepository.save(product);
    }
}
```

### Cache Configuration

```java
@Configuration
@EnableCaching
public class CacheConfig {
    
    @Bean
    public CacheManager cacheManager() {
        RedisCacheManager.Builder builder = RedisCacheManager
            .RedisCacheManagerBuilder
            .fromConnectionFactory(redisConnectionFactory())
            .cacheDefaults(cacheConfiguration(Duration.ofMinutes(10)));
        return builder.build();
    }
    
    private RedisCacheConfiguration cacheConfiguration(Duration ttl) {
        return RedisCacheConfiguration.defaultCacheConfig()
            .entryTtl(ttl)
            .disableCachingNullValues()
            .serializeValuesWith(RedisSerializationContext.SerializationPair
                .fromSerializer(new GenericJackson2JsonRedisSerializer()));
    }
}
```

---

## Database Design

### Connection Pooling
Efficient management of database connections.

```java
@Configuration
public class DatabaseConfig {
    @Bean
    public DataSource dataSource() {
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl("jdbc:mysql://localhost:3306/mydb");
        config.setMaximumPoolSize(20);
        config.setMinimumIdle(5);
        config.setConnectionTimeout(30000);
        config.setIdleTimeout(600000);
        config.setMaxLifetime(1800000);
        return new HikariDataSource(config);
    }
}
```

### Database Sharding
Distributing data across multiple database instances.

```java
@Component
public class ShardingStrategy {
    private Map<String, DataSource> shardDataSources;
    
    public String determineShardKey(Long userId) {
        return "shard_" + (userId % 4); // 4 shards
    }
    
    public DataSource getDataSource(String shardKey) {
        return shardDataSources.get(shardKey);
    }
}

@Repository
public class ShardedUserRepository {
    @Autowired
    private ShardingStrategy shardingStrategy;
    
    public User findById(Long userId) {
        String shardKey = shardingStrategy.determineShardKey(userId);
        DataSource dataSource = shardingStrategy.getDataSource(shardKey);
        
        JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
        return jdbcTemplate.queryForObject(
            "SELECT * FROM users WHERE id = ?", 
            User.class, userId
        );
    }
}
```

---

## Messaging and Queues

### Apache Kafka Integration
Implementing event-driven architecture with message queues.

```java
@Service
public class OrderEventProducer {
    @Autowired
    private KafkaTemplate<String, OrderEvent> kafkaTemplate;
    
    public void publishOrderEvent(OrderEvent event) {
        kafkaTemplate.send("order-events", event.getOrderId(), event);
    }
}

@Component
public class OrderEventConsumer {
    @Autowired
    private OrderProcessingService orderProcessingService;
    
    @KafkaListener(topics = "order-events", groupId = "order-processing-group")
    public void handleOrderEvent(OrderEvent event) {
        try {
            orderProcessingService.processOrder(event);
        } catch (Exception e) {
            // Handle processing errors
            handleProcessingError(event, e);
        }
    }
    
    private void handleProcessingError(OrderEvent event, Exception e) {
        // Send to dead letter queue or retry logic
        kafkaTemplate.send("order-events-dlq", event);
    }
}
```

### RabbitMQ Integration

```java
@Component
public class MessageProducer {
    @Autowired
    private RabbitTemplate rabbitTemplate;
    
    public void sendMessage(String exchange, String routingKey, Object message) {
        rabbitTemplate.convertAndSend(exchange, routingKey, message);
    }
}

@RabbitListener(queues = "notification.queue")
public void handleNotification(NotificationMessage message) {
    notificationService.sendNotification(message);
}
```

---

## Security

### JWT Authentication
Implementing token-based authentication.

```java
@Component
public class JwtTokenProvider {
    private String secretKey = "mySecretKey";
    private long validityInMilliseconds = 86400000; // 24 hours
    
    public String generateToken(String username, List<String> roles) {
        Claims claims = Jwts.claims().setSubject(username);
        claims.put("roles", roles);
        
        Date now = new Date();
        Date validity = new Date(now.getTime() + validityInMilliseconds);
        
        return Jwts.builder()
            .setClaims(claims)
            .setIssuedAt(now)
            .setExpiration(validity)
            .signWith(SignatureAlgorithm.HS256, secretKey)
            .compact();
    }
    
    public boolean validateToken(String token) {
        try {
            Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }
    
    public String getUsernameFromToken(String token) {
        return Jwts.parser()
            .setSigningKey(secretKey)
            .parseClaimsJws(token)
            .getBody()
            .getSubject();
    }
}
```

### Security Configuration

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf().disable()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .authorizeHttpRequests()
                .requestMatchers("/api/auth/**").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            .and()
            .addFilterBefore(jwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
        
        return http.build();
    }
    
    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter();
    }
}
```

---

## Monitoring and Observability

### Metrics with Micrometer
Collecting application metrics for monitoring.

```java
@RestController
public class MetricsController {
    private final MeterRegistry meterRegistry;
    private final Counter requestCounter;
    private final Timer responseTimer;
    
    public MetricsController(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
        this.requestCounter = Counter.builder("api.requests")
            .description("Total API requests")
            .register(meterRegistry);
        this.responseTimer = Timer.builder("api.response.time")
            .description("API response time")
            .register(meterRegistry);
    }
    
    @GetMapping("/api/data")
    public ResponseEntity<String> getData() {
        requestCounter.increment();
        Timer.Sample sample = Timer.start(meterRegistry);
        
        try {
            // Business logic
            Thread.sleep(100); // Simulate processing time
            return ResponseEntity.ok("data");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return ResponseEntity.status(500).body("Error");
        } finally {
            sample.stop(responseTimer);
        }
    }
}
```

### Health Checks

```java
@Component
public class DatabaseHealthIndicator implements HealthIndicator {
    @Autowired
    private DataSource dataSource;
    
    @Override
    public Health health() {
        try (Connection connection = dataSource.getConnection()) {
            if (connection.isValid(1)) {
                return Health.up()
                    .withDetail("database", "Available")
                    .withDetail("validationQuery", "SELECT 1")
                    .build();
            }
        } catch (SQLException e) {
            return Health.down()
                .withDetail("database", "Unavailable")
                .withException(e)
                .build();
        }
        return Health.down().withDetail("database", "Unavailable").build();
    }
}
```

---

## Fault Tolerance

### Circuit Breaker Pattern
Preventing cascading failures in distributed systems.

```java
@Component
public class ExternalServiceClient {
    private final CircuitBreaker circuitBreaker;
    private final RestTemplate restTemplate;
    
    public ExternalServiceClient() {
        this.circuitBreaker = CircuitBreaker.ofDefaults("externalService");
        this.restTemplate = new RestTemplate();
        
        // Configure circuit breaker
        circuitBreaker.getEventPublisher()
            .onStateTransition(event -> 
                System.out.println("Circuit breaker state transition: " + event));
    }
    
    public String callExternalService() {
        return circuitBreaker.executeSupplier(() -> {
            // Call to external service
            return restTemplate.getForObject("http://external-service/api/data", String.class);
        });
    }
}
```

### Retry Mechanism
Handling transient failures with retry logic.

```java
@Service
public class PaymentService {
    
    @Retryable(
        value = {PaymentException.class}, 
        maxAttempts = 3, 
        backoff = @Backoff(delay = 1000, multiplier = 2)
    )
    public PaymentResponse processPayment(PaymentRequest request) {
        // Payment processing logic that might fail
        try {
            return paymentGateway.process(request);
        } catch (ConnectException e) {
            throw new PaymentException("Payment gateway unavailable", e);
        }
    }
    
    @Recover
    public PaymentResponse recover(PaymentException ex, PaymentRequest request) {
        // Fallback logic when all retries fail
        return new PaymentResponse("FAILED", "Payment failed after retries: " + ex.getMessage());
    }
}
```

### Bulkhead Pattern

```java
@Configuration
public class ThreadPoolConfig {
    
    @Bean("userServiceExecutor")
    public Executor userServiceExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(10);
        executor.setMaxPoolSize(20);
        executor.setQueueCapacity(100);
        executor.setThreadNamePrefix("UserService-");
        executor.initialize();
        return executor;
    }
    
    @Bean("orderServiceExecutor")
    public Executor orderServiceExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(15);
        executor.setMaxPoolSize(30);
        executor.setQueueCapacity(200);
        executor.setThreadNamePrefix("OrderService-");
        executor.initialize();
        return executor;
    }
}

@Service
public class UserService {
    @Async("userServiceExecutor")
    public CompletableFuture<User> processUserAsync(Long userId) {
        // User processing logic in isolated thread pool
        return CompletableFuture.completedFuture(userRepository.findById(userId));
    }
}
```

---

## API Design

### RESTful API with Rate Limiting
Implementing proper API design with rate limiting.

```java
@RestController
@RequestMapping("/api/v1")
public class ApiController {
    
    @RateLimiter(name = "api-limiter", fallbackMethod = "rateLimitFallback")
    @GetMapping("/users")
    public ResponseEntity<List<User>> getUsers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(required = false) String sort) {
        
        Sort sortOrder = Sort.unsorted();
        if (sort != null && !sort.isEmpty()) {
            sortOrder = Sort.by(sort);
        }
        
        Pageable pageable = PageRequest.of(page, size, sortOrder);
        Page<User> users = userService.findAll(pageable);
        
        return ResponseEntity.ok()
            .header("X-Total-Count", String.valueOf(users.getTotalElements()))
            .header("X-Total-Pages", String.valueOf(users.getTotalPages()))
            .body(users.getContent());
    }
    
    @PostMapping("/users")
    public ResponseEntity<User> createUser(@Valid @RequestBody CreateUserRequest request) {
        User user = userService.createUser(request);
        return ResponseEntity.status(HttpStatus.CREATED)
            .location(URI.create("/api/v1/users/" + user.getId()))
            .body(user);
    }
    
    public ResponseEntity<String> rateLimitFallback(Exception ex) {
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
            .body("Rate limit exceeded. Please try again later.");
    }
}
```

### API Versioning

```java
@RestController
@RequestMapping("/api/v1/users")
public class UserControllerV1 {
    // Version 1 implementation
}

@RestController
@RequestMapping("/api/v2/users")
public class UserControllerV2 {
    // Version 2 implementation with new features
}
```

### Global Exception Handler

```java
@ControllerAdvice
public class GlobalExceptionHandler {
    
    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleUserNotFound(UserNotFoundException ex) {
        ErrorResponse error = new ErrorResponse("USER_NOT_FOUND", ex.getMessage());
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
    }
    
    @ExceptionHandler(ValidationException.class)
    public ResponseEntity<ErrorResponse> handleValidation(ValidationException ex) {
        ErrorResponse error = new ErrorResponse("VALIDATION_ERROR", ex.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
    }
    
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGeneral(Exception ex) {
        ErrorResponse error = new ErrorResponse("INTERNAL_ERROR", "An unexpected error occurred");
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
    }
}
```

---

## Best Practices Summary

1. **Stateless Design**: Keep services stateless for better scalability
2. **Idempotency**: Design operations to be idempotent where possible
3. **Graceful Degradation**: Implement fallback mechanisms
4. **Monitoring**: Add comprehensive logging and metrics
5. **Security**: Always validate input and implement proper authentication
6. **Documentation**: Maintain clear API documentation
7. **Testing**: Include unit, integration, and load testing
8. **Configuration Management**: Externalize configuration
9. **Database Optimization**: Use proper indexing and query optimization
10. **Asynchronous Processing**: Use async patterns for long-running operations

These examples provide a solid foundation for building scalable, reliable, and maintainable Java applications following system design principles.
