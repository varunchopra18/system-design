# Microservices Architecture Key Aspects with Java Examples

## Table of Contents
1. [Service Decomposition](#service-decomposition)
2. [Inter-Service Communication](#inter-service-communication)
3. [Service Discovery](#service-discovery)
4. [API Gateway](#api-gateway)
5. [Configuration Management](#configuration-management)
6. [Data Management](#data-management)
7. [Authentication & Authorization](#authentication--authorization)
8. [Monitoring & Observability](#monitoring--observability)
9. [Fault Tolerance & Resilience](#fault-tolerance--resilience)
10. [Event-Driven Architecture](#event-driven-architecture)
11. [Container Orchestration](#container-orchestration)
12. [Testing Strategies](#testing-strategies)

---

## Service Decomposition

### Domain-Driven Design (DDD)
Breaking down a monolithic application into smaller, independent services based on business domains.

```java
// User Service
@RestController
@RequestMapping("/api/users")
public class UserController {
    @Autowired
    private UserService userService;
    
    @GetMapping("/{id}")
    public ResponseEntity<User> getUser(@PathVariable Long id) {
        User user = userService.findById(id);
        return ResponseEntity.ok(user);
    }
    
    @PostMapping
    public ResponseEntity<User> createUser(@Valid @RequestBody CreateUserRequest request) {
        User user = userService.createUser(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(user);
    }
}

// Order Service
@RestController
@RequestMapping("/api/orders")
public class OrderController {
    @Autowired
    private OrderService orderService;
    
    @PostMapping
    public ResponseEntity<Order> createOrder(@Valid @RequestBody CreateOrderRequest request) {
        Order order = orderService.createOrder(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(order);
    }
    
    @GetMapping("/user/{userId}")
    public ResponseEntity<List<Order>> getOrdersByUser(@PathVariable Long userId) {
        List<Order> orders = orderService.findByUserId(userId);
        return ResponseEntity.ok(orders);
    }
}
```

### Bounded Context Implementation

```java
// User Service Domain
@Entity
@Table(name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false, unique = true)
    private String email;
    
    @Column(nullable = false)
    private String firstName;
    
    @Column(nullable = false)
    private String lastName;
    
    @Enumerated(EnumType.STRING)
    private UserStatus status;
    
    // getters and setters
}

// Order Service Domain
@Entity
@Table(name = "orders")
public class Order {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false)
    private Long userId; // Reference to User service
    
    @Column(nullable = false)
    private BigDecimal totalAmount;
    
    @Enumerated(EnumType.STRING)
    private OrderStatus status;
    
    @OneToMany(mappedBy = "order", cascade = CascadeType.ALL)
    private List<OrderItem> items;
    
    // getters and setters
}
```

---

## Inter-Service Communication

### Synchronous Communication (REST)

```java
// HTTP Client using RestTemplate
@Service
public class UserServiceClient {
    @Autowired
    private RestTemplate restTemplate;
    
    @Value("${user.service.url}")
    private String userServiceUrl;
    
    public User getUserById(Long userId) {
        try {
            String url = userServiceUrl + "/api/users/" + userId;
            return restTemplate.getForObject(url, User.class);
        } catch (RestClientException e) {
            throw new UserServiceException("Failed to fetch user", e);
        }
    }
}

// Using OpenFeign for declarative REST clients
@FeignClient(name = "user-service", url = "${user.service.url}")
public interface UserServiceClient {
    @GetMapping("/api/users/{id}")
    User getUserById(@PathVariable("id") Long id);
    
    @PostMapping("/api/users")
    User createUser(@RequestBody CreateUserRequest request);
}
```

### Asynchronous Communication (Message Queues)

```java
// RabbitMQ Publisher
@Service
public class OrderEventPublisher {
    @Autowired
    private RabbitTemplate rabbitTemplate;
    
    public void publishOrderCreated(OrderCreatedEvent event) {
        rabbitTemplate.convertAndSend("order.exchange", "order.created", event);
    }
}

// RabbitMQ Consumer
@Component
public class OrderEventConsumer {
    @Autowired
    private InventoryService inventoryService;
    
    @RabbitListener(queues = "inventory.order.created")
    public void handleOrderCreated(OrderCreatedEvent event) {
        inventoryService.reserveItems(event.getOrderId(), event.getItems());
    }
}

// Event Classes
public class OrderCreatedEvent {
    private Long orderId;
    private Long userId;
    private List<OrderItem> items;
    private LocalDateTime timestamp;
    
    // constructors, getters, setters
}
```

---

## Service Discovery

### Eureka Service Registration

```java
// Eureka Server
@SpringBootApplication
@EnableEurekaServer
public class EurekaServerApplication {
    public static void main(String[] args) {
        SpringApplication.run(EurekaServerApplication.class, args);
    }
}

// Service Registration
@SpringBootApplication
@EnableEurekaClient
public class UserServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(UserServiceApplication.class, args);
    }
}
```

### Service Discovery Configuration

```yaml
# application.yml for User Service
eureka:
  client:
    service-url:
      defaultZone: http://localhost:8761/eureka/
  instance:
    prefer-ip-address: true
    
spring:
  application:
    name: user-service
  profiles:
    active: dev
    
server:
  port: 8081
```

### Load Balanced Service Communication

```java
@Configuration
public class RestTemplateConfig {
    @Bean
    @LoadBalanced
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}

@Service
public class OrderService {
    @Autowired
    private RestTemplate restTemplate;
    
    public User getUserForOrder(Long userId) {
        // Service name instead of hardcoded URL
        return restTemplate.getForObject("http://user-service/api/users/" + userId, User.class);
    }
}
```

---

## API Gateway

### Spring Cloud Gateway Implementation

```java
@SpringBootApplication
public class ApiGatewayApplication {
    public static void main(String[] args) {
        SpringApplication.run(ApiGatewayApplication.class, args);
    }
}

@Configuration
public class GatewayConfig {
    
    @Bean
    public RouteLocator customRouteLocator(RouteLocatorBuilder builder) {
        return builder.routes()
            .route("user-service", r -> r.path("/api/users/**")
                .uri("lb://user-service"))
            .route("order-service", r -> r.path("/api/orders/**")
                .uri("lb://order-service"))
            .route("inventory-service", r -> r.path("/api/inventory/**")
                .uri("lb://inventory-service"))
            .build();
    }
}
```

### Gateway Filters

```java
@Component
public class AuthenticationFilter implements GatewayFilter {
    
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        
        if (!request.getHeaders().containsKey("Authorization")) {
            return onError(exchange, "Missing Authorization header", HttpStatus.UNAUTHORIZED);
        }
        
        String token = request.getHeaders().getFirst("Authorization");
        if (!isValidToken(token)) {
            return onError(exchange, "Invalid token", HttpStatus.UNAUTHORIZED);
        }
        
        return chain.filter(exchange);
    }
    
    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        return response.setComplete();
    }
    
    private boolean isValidToken(String token) {
        // JWT validation logic
        return true;
    }
}
```

### Rate Limiting

```java
@Configuration
public class RateLimitingConfig {
    
    @Bean
    public RedisRateLimiter redisRateLimiter() {
        return new RedisRateLimiter(10, 20, 1); // 10 requests per second, burst capacity 20
    }
    
    @Bean
    public RouteLocator rateLimitedRoutes(RouteLocatorBuilder builder) {
        return builder.routes()
            .route("user-service-rate-limited", r -> r.path("/api/users/**")
                .filters(f -> f.requestRateLimiter(config -> config
                    .setRateLimiter(redisRateLimiter())
                    .setKeyResolver(exchange -> Mono.just("user-api"))))
                .uri("lb://user-service"))
            .build();
    }
}
```

---

## Configuration Management

### Spring Cloud Config Server

```java
@SpringBootApplication
@EnableConfigServer
public class ConfigServerApplication {
    public static void main(String[] args) {
        SpringApplication.run(ConfigServerApplication.class, args);
    }
}
```

### Configuration Properties

```yaml
# application.yml in Config Server
spring:
  cloud:
    config:
      server:
        git:
          uri: https://github.com/your-org/config-repo
          clone-on-start: true
          default-label: main
```

### Client Configuration

```java
@RestController
@RefreshScope
public class ConfigTestController {
    
    @Value("${app.message:Default Message}")
    private String message;
    
    @GetMapping("/config")
    public Map<String, String> getConfig() {
        return Collections.singletonMap("message", message);
    }
}
```

---

## Data Management

### Database Per Service

```java
// User Service Database Configuration
@Configuration
@EnableJpaRepositories(
    basePackages = "com.example.userservice.repository",
    entityManagerFactoryRef = "userEntityManagerFactory",
    transactionManagerRef = "userTransactionManager"
)
public class UserDatabaseConfig {
    
    @Primary
    @Bean
    @ConfigurationProperties("spring.datasource.user")
    public DataSource userDataSource() {
        return DataSourceBuilder.create().build();
    }
    
    @Primary
    @Bean
    public LocalContainerEntityManagerFactoryBean userEntityManagerFactory() {
        LocalContainerEntityManagerFactoryBean factory = new LocalContainerEntityManagerFactoryBean();
        factory.setDataSource(userDataSource());
        factory.setPackagesToScan("com.example.userservice.entity");
        factory.setJpaVendorAdapter(new HibernateJpaVendorAdapter());
        return factory;
    }
}
```

### Event Sourcing

```java
@Entity
public class EventStore {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(nullable = false)
    private String aggregateId;
    
    @Column(nullable = false)
    private String eventType;
    
    @Column(nullable = false, columnDefinition = "TEXT")
    private String eventData;
    
    @Column(nullable = false)
    private LocalDateTime timestamp;
    
    @Column(nullable = false)
    private Long version;
    
    // getters and setters
}

@Service
public class EventStoreService {
    @Autowired
    private EventStoreRepository eventStoreRepository;
    
    @Autowired
    private ObjectMapper objectMapper;
    
    public void saveEvent(String aggregateId, Object event, Long version) {
        try {
            EventStore eventStore = new EventStore();
            eventStore.setAggregateId(aggregateId);
            eventStore.setEventType(event.getClass().getSimpleName());
            eventStore.setEventData(objectMapper.writeValueAsString(event));
            eventStore.setTimestamp(LocalDateTime.now());
            eventStore.setVersion(version);
            
            eventStoreRepository.save(eventStore);
        } catch (JsonProcessingException e) {
            throw new EventStoreException("Failed to serialize event", e);
        }
    }
    
    public List<Object> getEvents(String aggregateId) {
        List<EventStore> events = eventStoreRepository.findByAggregateIdOrderByVersion(aggregateId);
        return events.stream()
            .map(this::deserializeEvent)
            .collect(Collectors.toList());
    }
}
```

### Saga Pattern

```java
@Service
public class OrderSagaOrchestrator {
    
    @Autowired
    private PaymentService paymentService;
    
    @Autowired
    private InventoryService inventoryService;
    
    @Autowired
    private ShippingService shippingService;
    
    @Transactional
    public void processOrder(Order order) {
        try {
            // Step 1: Reserve inventory
            inventoryService.reserveItems(order.getItems());
            
            // Step 2: Process payment
            PaymentResult paymentResult = paymentService.processPayment(order.getPaymentInfo());
            
            if (paymentResult.isSuccess()) {
                // Step 3: Create shipment
                shippingService.createShipment(order);
                
                // Step 4: Confirm inventory
                inventoryService.confirmReservation(order.getItems());
            } else {
                // Compensate: Release inventory
                inventoryService.releaseReservation(order.getItems());
                throw new OrderProcessingException("Payment failed");
            }
            
        } catch (Exception e) {
            // Compensating actions
            compensateOrder(order);
            throw e;
        }
    }
    
    private void compensateOrder(Order order) {
        try {
            inventoryService.releaseReservation(order.getItems());
            paymentService.refundPayment(order.getPaymentInfo());
        } catch (Exception e) {
            // Log compensation failure
            log.error("Compensation failed for order: {}", order.getId(), e);
        }
    }
}
```

---

## Authentication & Authorization

### JWT Token Service

```java
@Service
public class JwtTokenService {
    @Value("${jwt.secret}")
    private String jwtSecret;
    
    @Value("${jwt.expiration}")
    private int jwtExpiration;
    
    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", userDetails.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .collect(Collectors.toList()));
        
        return createToken(claims, userDetails.getUsername());
    }
    
    private String createToken(Map<String, Object> claims, String subject) {
        return Jwts.builder()
            .setClaims(claims)
            .setSubject(subject)
            .setIssuedAt(new Date(System.currentTimeMillis()))
            .setExpiration(new Date(System.currentTimeMillis() + jwtExpiration * 1000))
            .signWith(SignatureAlgorithm.HS512, jwtSecret)
            .compact();
    }
    
    public boolean validateToken(String token, UserDetails userDetails) {
        final String username = getUsernameFromToken(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}
```

### OAuth2 Resource Server

```java
@Configuration
@EnableResourceServer
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {
    
    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
            .antMatchers("/api/public/**").permitAll()
            .antMatchers(HttpMethod.GET, "/api/users/**").hasRole("USER")
            .antMatchers(HttpMethod.POST, "/api/users/**").hasRole("ADMIN")
            .anyRequest().authenticated();
    }
    
    @Bean
    public TokenStore tokenStore() {
        return new JwtTokenStore(jwtAccessTokenConverter());
    }
    
    @Bean
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setSigningKey("mySecretKey");
        return converter;
    }
}
```

---

## Monitoring & Observability

### Distributed Tracing with Zipkin

```java
@Configuration
public class TracingConfig {
    
    @Bean
    public Sender sender() {
        return OkHttpSender.create("http://localhost:9411/api/v2/spans");
    }
    
    @Bean
    public AsyncReporter<Span> spanReporter() {
        return AsyncReporter.create(sender());
    }
    
    @Bean
    public Tracing tracing() {
        return Tracing.newBuilder()
            .localServiceName("user-service")
            .spanReporter(spanReporter())
            .sampler(Sampler.create(1.0f))
            .build();
    }
}
```

### Custom Metrics

```java
@RestController
public class MetricsController {
    private final MeterRegistry meterRegistry;
    private final Counter orderCounter;
    private final Timer orderProcessingTimer;
    
    public MetricsController(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
        this.orderCounter = Counter.builder("orders.created")
            .description("Number of orders created")
            .tag("service", "order-service")
            .register(meterRegistry);
        
        this.orderProcessingTimer = Timer.builder("order.processing.time")
            .description("Order processing time")
            .register(meterRegistry);
    }
    
    @PostMapping("/orders")
    public ResponseEntity<Order> createOrder(@RequestBody CreateOrderRequest request) {
        return Timer.Sample.start(meterRegistry)
            .stop(orderProcessingTimer.recordCallable(() -> {
                Order order = orderService.createOrder(request);
                orderCounter.increment();
                return ResponseEntity.ok(order);
            }));
    }
}
```

### Health Checks

```java
@Component
public class CustomHealthIndicator implements HealthIndicator {
    
    @Autowired
    private ExternalServiceClient externalServiceClient;
    
    @Override
    public Health health() {
        try {
            externalServiceClient.healthCheck();
            return Health.up()
                .withDetail("external-service", "Available")
                .withDetail("timestamp", LocalDateTime.now())
                .build();
        } catch (Exception e) {
            return Health.down()
                .withDetail("external-service", "Unavailable")
                .withDetail("error", e.getMessage())
                .build();
        }
    }
}
```

---

## Fault Tolerance & Resilience

### Circuit Breaker with Resilience4j

```java
@Service
public class PaymentService {
    
    @CircuitBreaker(name = "payment-service", fallbackMethod = "fallbackPayment")
    @Retry(name = "payment-service")
    @TimeLimiter(name = "payment-service")
    public CompletableFuture<PaymentResponse> processPayment(PaymentRequest request) {
        return CompletableFuture.supplyAsync(() -> {
            // Call external payment service
            return externalPaymentService.processPayment(request);
        });
    }
    
    public CompletableFuture<PaymentResponse> fallbackPayment(PaymentRequest request, Exception ex) {
        return CompletableFuture.completedFuture(
            new PaymentResponse("FAILED", "Payment service unavailable")
        );
    }
}
```

### Configuration for Resilience4j

```yaml
resilience4j:
  circuitbreaker:
    instances:
      payment-service:
        registerHealthIndicator: true
        slidingWindowSize: 10
        minimumNumberOfCalls: 5
        permittedNumberOfCallsInHalfOpenState: 3
        automaticTransitionFromOpenToHalfOpenEnabled: true
        waitDurationInOpenState: 5s
        failureRateThreshold: 50
        eventConsumerBufferSize: 10
        
  retry:
    instances:
      payment-service:
        maxRetryAttempts: 3
        waitDuration: 1s
        enableExponentialBackoff: true
        exponentialBackoffMultiplier: 2
        
  timelimiter:
    instances:
      payment-service:
        timeoutDuration: 3s
        cancelRunningFuture: true
```

### Bulkhead Pattern

```java
@Configuration
public class BulkheadConfig {
    
    @Bean("paymentExecutor")
    public Executor paymentExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(5);
        executor.setMaxPoolSize(10);
        executor.setQueueCapacity(25);
        executor.setThreadNamePrefix("Payment-");
        executor.initialize();
        return executor;
    }
    
    @Bean("notificationExecutor")
    public Executor notificationExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(3);
        executor.setMaxPoolSize(5);
        executor.setQueueCapacity(15);
        executor.setThreadNamePrefix("Notification-");
        executor.initialize();
        return executor;
    }
}

@Service
public class OrderService {
    
    @Async("paymentExecutor")
    public CompletableFuture<PaymentResponse> processPaymentAsync(PaymentRequest request) {
        return paymentService.processPayment(request);
    }
    
    @Async("notificationExecutor")
    public CompletableFuture<Void> sendNotificationAsync(NotificationRequest request) {
        notificationService.sendNotification(request);
        return CompletableFuture.completedFuture(null);
    }
}
```

---

## Event-Driven Architecture

### Event Bus Implementation

```java
@Component
public class EventBus {
    private final ApplicationEventPublisher eventPublisher;
    
    public EventBus(ApplicationEventPublisher eventPublisher) {
        this.eventPublisher = eventPublisher;
    }
    
    public void publish(DomainEvent event) {
        eventPublisher.publishEvent(event);
    }
}

// Domain Event
public abstract class DomainEvent {
    private final String eventId;
    private final LocalDateTime occurredOn;
    
    protected DomainEvent() {
        this.eventId = UUID.randomUUID().toString();
        this.occurredOn = LocalDateTime.now();
    }
    
    // getters
}

// Specific Event
public class OrderCreatedEvent extends DomainEvent {
    private final Long orderId;
    private final Long customerId;
    private final BigDecimal amount;
    
    public OrderCreatedEvent(Long orderId, Long customerId, BigDecimal amount) {
        super();
        this.orderId = orderId;
        this.customerId = customerId;
        this.amount = amount;
    }
    
    // getters
}
```

### Event Handlers

```java
@Component
public class OrderEventHandler {
    
    @Autowired
    private InventoryService inventoryService;
    
    @Autowired
    private EmailService emailService;
    
    @EventListener
    @Async
    public void handleOrderCreated(OrderCreatedEvent event) {
        // Reserve inventory
        inventoryService.reserveInventory(event.getOrderId());
        
        // Send confirmation email
        emailService.sendOrderConfirmation(event.getCustomerId(), event.getOrderId());
    }
    
    @EventListener
    public void handlePaymentProcessed(PaymentProcessedEvent event) {
        if (event.isSuccessful()) {
            // Confirm inventory reservation
            inventoryService.confirmReservation(event.getOrderId());
        } else {
            // Release inventory
            inventoryService.releaseReservation(event.getOrderId());
        }
    }
}
```

### CQRS Implementation

```java
// Command Side
@Service
public class OrderCommandService {
    
    @Autowired
    private OrderRepository orderRepository;
    
    @Autowired
    private EventBus eventBus;
    
    @Transactional
    public Order createOrder(CreateOrderCommand command) {
        Order order = new Order();
        order.setCustomerId(command.getCustomerId());
        order.setItems(command.getItems());
        order.setStatus(OrderStatus.PENDING);
        
        Order savedOrder = orderRepository.save(order);
        
        // Publish event
        eventBus.publish(new OrderCreatedEvent(
            savedOrder.getId(),
            savedOrder.getCustomerId(),
            savedOrder.getTotalAmount()
        ));
        
        return savedOrder;
    }
}

// Query Side
@Service
public class OrderQueryService {
    
    @Autowired
    private OrderReadModelRepository orderReadModelRepository;
    
    public List<OrderReadModel> getOrdersByCustomer(Long customerId) {
        return orderReadModelRepository.findByCustomerId(customerId);
    }
    
    public OrderReadModel getOrderById(Long orderId) {
        return orderReadModelRepository.findById(orderId)
            .orElseThrow(() -> new OrderNotFoundException("Order not found: " + orderId));
    }
}

// Read Model
@Entity
@Table(name = "order_read_model")
public class OrderReadModel {
    @Id
    private Long id;
    private Long customerId;
    private String customerName;
    private BigDecimal totalAmount;
    private OrderStatus status;
    private LocalDateTime createdAt;
    private String items; // JSON string
    
    // getters and setters
}
```

---

## Container Orchestration

### Docker Configuration

```dockerfile
# Dockerfile for microservice
FROM openjdk:11-jre-slim

VOLUME /tmp

COPY target/user-service-1.0.0.jar app.jar

ENTRYPOINT ["java", "-jar", "/app.jar"]

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/actuator/health || exit 1
```

### Kubernetes Deployment

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: user-service
spec:
  replicas: 3
  selector:
    matchLabels:
      app: user-service
  template:
    metadata:
      labels:
        app: user-service
    spec:
      containers:
      - name: user-service
        image: user-service:latest
        ports:
        - containerPort: 8080
        env:
        - name: SPRING_PROFILES_ACTIVE
          value: "kubernetes"
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: db-secret
              key: url
        livenessProbe:
          httpGet:
            path: /actuator/health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /actuator/health
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5

---
apiVersion: v1
kind: Service
metadata:
  name: user-service
spec:
  selector:
    app: user-service
  ports:
  - protocol: TCP
    port: 80
    targetPort: 8080
  type: LoadBalancer
```

---

## Testing Strategies

### Unit Testing

```java
@ExtendWith(MockitoExtension.class)
class UserServiceTest {
    
    @Mock
    private UserRepository userRepository;
    
    @Mock
    private EventBus eventBus;
    
    @InjectMocks
    private UserService userService;
    
    @Test
    void shouldCreateUser() {
        // Given
        CreateUserRequest request = new CreateUserRequest("john@example.com", "John", "Doe");
        User savedUser = new User(1L, "john@example.com", "John", "Doe");
        
        when(userRepository.save(any(User.class))).thenReturn(savedUser);
        
        // When
        User result = userService.createUser(request);
        
        // Then
        assertThat(result).isNotNull();
        assertThat(result.getEmail()).isEqualTo("john@example.com");
        verify(eventBus).publish(any(UserCreatedEvent.class));
    }
}
```

### Integration Testing

```java
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
class UserServiceIntegrationTest {
    
    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:13")
            .withDatabaseName("testdb")
            .withUsername("test")
            .withPassword("test");
    
    @Autowired
    private TestRestTemplate restTemplate;
    
    @Autowired
    private UserRepository userRepository;
    
    @Test
    void shouldCreateAndRetrieveUser() {
        // Given
        CreateUserRequest request = new CreateUserRequest("test@example.com", "Test", "User");
        
        // When
        ResponseEntity<User> createResponse = restTemplate.postForEntity("/api/users", request, User.class);
        
        // Then
        assertThat(createResponse.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(createResponse.getBody().getEmail()).isEqualTo("test@example.com");
        
        Long userId = createResponse.getBody().getId();
        User retrievedUser = userRepository.findById(userId).orElse(null);
        assertThat(retrievedUser).isNotNull();
    }
}
```

### Contract Testing with Pact

```java
@ExtendWith(PactConsumerTestExt.class)
@PactTestFor(providerName = "user-service")
public class UserServiceContractTest {
    
    @MockServerConfig
    private MockServerConfigBuilder mockServerConfig = MockServerConfigBuilder.mockServerConfig();
    
    @Pact(consumer = "order-service")
    public RequestResponsePact getUserById(PactDslWithProvider builder) {
        return builder
            .given("user exists")
            .uponReceiving("get user by id")
            .path("/api/users/1")
            .method("GET")
            .willRespondWith()
            .status(200)
            .headers(Map.of("Content-Type", "application/json"))
            .body(new PactDslJsonBody()
                .integerType("id", 1)
                .stringType("email", "john@example.com")
                .stringType("firstName", "John")
                .stringType("lastName", "Doe"))
            .toPact();
    }
    
    @Test
    @PactTestFor(pactMethod = "getUserById")
    void shouldGetUserById(MockServer mockServer) {
        // Given
        String baseUrl = mockServer.getUrl();
        UserServiceClient client = new UserServiceClient(baseUrl);
        
        // When
        User user = client.getUserById(1L);
        
        // Then
        assertThat(user).isNotNull();
        assertThat(user.getId()).isEqualTo(1L);
        assertThat(user.getEmail()).isEqualTo("john@example.com");
    }
}
```

### Load Testing with JMeter Integration

```java
@Component
public class LoadTestDataGenerator {
    
    public void generateTestUsers(int count) {
        for (int i = 0; i < count; i++) {
            CreateUserRequest request = new CreateUserRequest(
                "user" + i + "@example.com",
                "User" + i,
                "LastName" + i
            );
            // Create test data
        }
    }
}
```

---

## Security Considerations

### API Security

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
                .requestMatchers("/actuator/health").permitAll()
                .requestMatchers("/api/public/**").permitAll()
                .requestMatchers(HttpMethod.GET, "/api/users/**").hasRole("USER")
                .requestMatchers(HttpMethod.POST, "/api/users/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            .and()
            .oauth2ResourceServer()
                .jwt()
                .jwtDecoder(jwtDecoder());
        
        return http.build();
    }
    
    @Bean
    public JwtDecoder jwtDecoder() {
        return JwtDecoders.fromIssuerLocation("https://your-auth-server.com");
    }
}
```

### Input Validation

```java
@RestController
@Validated
public class UserController {
    
    @PostMapping("/api/users")
    public ResponseEntity<User> createUser(@Valid @RequestBody CreateUserRequest request) {
        User user = userService.createUser(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(user);
    }
}

public class CreateUserRequest {
    @NotBlank(message = "Email is required")
    @Email(message = "Email should be valid")
    private String email;
    
    @NotBlank(message = "First name is required")
    @Size(min = 2, max = 50, message = "First name must be between 2 and 50 characters")
    private String firstName;
    
    @NotBlank(message = "Last name is required")
    @Size(min = 2, max = 50, message = "Last name must be between 2 and 50 characters")
    private String lastName;
    
    // getters and setters
}
```

---

## Performance Optimization

### Caching Strategies

```java
@Service
public class UserService {
    
    @Cacheable(value = "users", key = "#id")
    public User getUserById(Long id) {
        return userRepository.findById(id)
            .orElseThrow(() -> new UserNotFoundException("User not found"));
    }
    
    @CacheEvict(value = "users", key = "#user.id")
    public User updateUser(User user) {
        return userRepository.save(user);
    }
    
    @CacheEvict(value = "users", allEntries = true)
    public void clearUserCache() {
        // Clear all user cache entries
    }
}
```

### Database Connection Pooling

```java
@Configuration
public class DatabaseConfig {
    
    @Bean
    @Primary
    @ConfigurationProperties("spring.datasource.user")
    public DataSource userDataSource() {
        return DataSourceBuilder.create()
            .type(HikariDataSource.class)
            .build();
    }
    
    @Bean
    @ConfigurationProperties("spring.datasource.user.hikari")
    public HikariConfig userHikariConfig() {
        HikariConfig config = new HikariConfig();
        config.setMaximumPoolSize(20);
        config.setMinimumIdle(5);
        config.setConnectionTimeout(30000);
        config.setIdleTimeout(600000);
        config.setMaxLifetime(1800000);
        config.setLeakDetectionThreshold(60000);
        return config;
    }
}
```

---

## Deployment Strategies

### Blue-Green Deployment

```yaml
# blue-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: user-service-blue
  labels:
    app: user-service
    version: blue
spec:
  replicas: 3
  selector:
    matchLabels:
      app: user-service
      version: blue
  template:
    metadata:
      labels:
        app: user-service
        version: blue
    spec:
      containers:
      - name: user-service
        image: user-service:v1.0.0
        ports:
        - containerPort: 8080

---
# green-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: user-service-green
  labels:
    app: user-service
    version: green
spec:
  replicas: 3
  selector:
    matchLabels:
      app: user-service
      version: green
  template:
    metadata:
      labels:
        app: user-service
        version: green
    spec:
      containers:
      - name: user-service
        image: user-service:v2.0.0
        ports:
        - containerPort: 8080

---
# service.yaml
apiVersion: v1
kind: Service
metadata:
  name: user-service
spec:
  selector:
    app: user-service
    version: blue  # Switch to green for deployment
  ports:
  - port: 80
    targetPort: 8080
```

### Canary Deployment

```yaml
# canary-deployment.yaml
apiVersion: argoproj.io/v1alpha1
kind: Rollout
metadata:
  name: user-service-rollout
spec:
  replicas: 10
  strategy:
    canary:
      steps:
      - setWeight: 20
      - pause: {}
      - setWeight: 40
      - pause: {duration: 10}
      - setWeight: 60
      - pause: {duration: 10}
      - setWeight: 80
      - pause: {duration: 10}
      canaryService: user-service-canary
      stableService: user-service-stable
  selector:
    matchLabels:
      app: user-service
  template:
    metadata:
      labels:
        app: user-service
    spec:
      containers:
      - name: user-service
        image: user-service:latest
        ports:
        - containerPort: 8080
```

---

## Best Practices Summary

### Design Principles

1. **Single Responsibility**: Each microservice should have a single business purpose
2. **Autonomous**: Services should be independently deployable and scalable
3. **Decentralized**: Avoid centralized data management and governance
4. **Resilient**: Design for failure and implement fault tolerance
5. **Observable**: Implement comprehensive monitoring and logging
6. **Secure**: Implement security at every layer

### Development Guidelines

1. **API-First Design**: Design APIs before implementation
2. **Database Per Service**: Each service should have its own database
3. **Stateless Services**: Keep services stateless for better scalability
4. **Event-Driven Communication**: Use events for loose coupling
5. **Idempotent Operations**: Ensure operations can be safely retried
6. **Graceful Degradation**: Implement fallback mechanisms

### Operational Practices

1. **Automated Testing**: Implement comprehensive test strategies
2. **CI/CD Pipelines**: Automate build, test, and deployment processes
3. **Infrastructure as Code**: Use tools like Terraform or Helm
4. **Monitoring and Alerting**: Implement proactive monitoring
5. **Distributed Tracing**: Track requests across services
6. **Capacity Planning**: Monitor and plan for scaling needs

### Common Pitfalls to Avoid

1. **Distributed Monolith**: Avoid creating tightly coupled services
2. **Chatty Interfaces**: Minimize inter-service communication
3. **Shared Databases**: Don't share databases between services
4. **Synchronous Communication**: Use async communication where possible
5. **Lack of Service Boundaries**: Define clear service boundaries
6. **Insufficient Monitoring**: Don't underestimate observability needs

---

## Conclusion

Microservices architecture provides numerous benefits including scalability, technology diversity, and team autonomy. However, it also introduces complexity in terms of distributed systems challenges. The key to success lies in proper service decomposition, robust communication patterns, comprehensive monitoring, and strong operational practices.

The examples provided in this guide demonstrate practical implementations of microservices patterns using Java and Spring Boot ecosystem. These patterns should be adapted based on specific requirements and constraints of your system.

Remember that microservices are not a silver bullet - they should be adopted when the benefits outweigh the added complexity, typically in organizations with multiple teams working on complex, large-scale systems.
