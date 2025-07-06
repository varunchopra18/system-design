## Inter-Service Communication Patterns

### 1. Synchronous Communication

#### RestTemplate with Load Balancing
```java
@Configuration
public class RestTemplateConfig {
    
    @Bean
    @LoadBalanced
    public RestTemplate restTemplate() {
        RestTemplate restTemplate = new RestTemplate();
        
        // Add custom interceptors
        restTemplate.getInterceptors().add(new LoggingInterceptor());
        restTemplate.getInterceptors().add(new RetryInterceptor());
        
        return restTemplate;
    }
}

@Component
public class LoggingInterceptor implements ClientHttpRequestInterceptor {
    
    private static final Logger logger = LoggerFactory.getLogger(LoggingInterceptor.class);
    
    @Override
    public ClientHttpResponse intercept(
            HttpRequest request, 
            byte[] body, 
            ClientHttpRequestExecution execution) throws IOException {
        
        logger.info("Request URI: {}", request.getURI());
        logger.info("Request Method: {}", request.getMethod());
        
        ClientHttpResponse response = execution.execute(request, body);
        
        logger.info("Response Status: {}", response.getStatusCode());
        
        return response;
    }
}

@Service
public class ProductService {
    
    @Autowired
    private RestTemplate restTemplate;
    
    public Product getProductDetails(Long productId) {
        try {
            String url = "http://product-service/products/" + productId;
            
            HttpHeaders headers = new HttpHeaders();
            headers.set("Authorization", "Bearer " + getAuthToken());
            HttpEntity<String> entity = new HttpEntity<>(headers);
            
            ResponseEntity<Product> response = restTemplate.exchange(
                url, HttpMethod.GET, entity, Product.class);
            
            return response.getBody();
        } catch (ResourceAccessException e) {
            throw new ServiceUnavailableException("Product service is unavailable", e);
        } catch (HttpClientErrorException e) {
            if (e.getStatusCode() == HttpStatus.NOT_FOUND) {
                throw new ProductNotFoundException("Product not found: " + productId);
            }
            throw new ServiceException("Error fetching product details", e);
        }
    }
    
    private String getAuthToken() {
        // Implementation for getting auth token
        return "jwt-token-here";
    }
}
```

#### Feign Client with Circuit Breaker
```java
@FeignClient(
    name = "product-service", 
    fallback = ProductServiceFallback.class,
    configuration = FeignConfig.class
)
public interface ProductServiceClient {
    
    @GetMapping("/products/{id}")
    Product getProduct(@PathVariable("id") Long id);
    
    @GetMapping("/products")
    List<Product> getAllProducts();
    
    @PostMapping("/products")
    Product createProduct(@RequestBody Product product);
    
    @PutMapping("/products/{id}")
    Product updateProduct(@PathVariable("id") Long id, @RequestBody Product product);
    
    @DeleteMapping("/products/{id}")
    void deleteProduct(@PathVariable("id") Long id);
    
    @GetMapping("/products/search")
    List<Product> searchProducts(@RequestParam String query);
}

@Component
public class ProductServiceFallback implements ProductServiceClient {
    
    private static final Logger logger = LoggerFactory.getLogger(ProductServiceFallback.class);
    
    @Override
    public Product getProduct(Long id) {
        logger.warn("Fallback: Getting product with id {}", id);
        Product fallbackProduct = new Product();
        fallbackProduct.setId(id);
        fallbackProduct.setName("Product Unavailable");
        fallbackProduct.setPrice(BigDecimal.ZERO);
        fallbackProduct.setAvailable(false);
        return fallbackProduct;
    }
    
    @Override
    public List<Product> getAllProducts() {
        logger.warn("Fallback: Getting all products");
        return Collections.emptyList();
    }
    
    @Override
    public Product createProduct(Product product) {
        logger.error("Fallback: Cannot create product - service unavailable");
        throw new ServiceUnavailableException("Product service is unavailable");
    }
    
    @Override
    public Product updateProduct(Long id, Product product) {
        logger.error("Fallback: Cannot update product {} - service unavailable", id);
        throw new ServiceUnavailableException("Product service is unavailable");
    }
    
    @Override
    public void deleteProduct(Long id) {
        logger.error("Fallback: Cannot delete product {} - service unavailable", id);
        throw new ServiceUnavailableException("Product service is unavailable");
    }
    
    @Override
    public List<Product> searchProducts(String query) {
        logger.warn("Fallback: Search products with query {}", query);
        return Collections.emptyList();
    }
}

@Configuration
public class FeignConfig {
    
    @Bean
    public RequestInterceptor requestInterceptor() {
        return new RequestInterceptor() {
            @Override
            public void apply(RequestTemplate template) {
                // Add authentication headers
                template.header("Authorization", "Bearer " + getCurrentToken());
                template.header("X-Request-ID", UUID.randomUUID().toString());
                template.header("Content-Type", "application/json");
            }
        };
    }
    
    @Bean
    public ErrorDecoder errorDecoder() {
        return new CustomErrorDecoder();
    }
    
    @Bean
    public Retryer retryer() {
        return new Retryer.Default(100, 1000, 3);
    }
    
    private String getCurrentToken() {
        // Implementation to get current authentication token
        return "jwt-token-here";
    }
}

public class CustomErrorDecoder implements ErrorDecoder {
    
    @Override
    public Exception decode(String methodKey, Response response) {
        switch (response.status()) {
            case 400:
                return new BadRequestException("Bad request to " + methodKey);
            case 404:
                return new NotFoundException("Resource not found for " + methodKey);
            case 500:
                return new InternalServerException("Internal server error for " + methodKey);
            default:
                return new Exception("Generic error for " + methodKey);
        }
    }
}
```

### 2. Asynchronous Communication

#### Using Spring Cloud Stream with RabbitMQ/Kafka
```java
// Producer Service
@Service
public class OrderEventPublisher {
    
    @Autowired
    private RabbitTemplate rabbitTemplate;
    
    public void publishOrderCreated(Order order) {
        OrderEvent event = new OrderEvent();
        event.setOrderId(order.getId());
        event.setUserId(order.getUserId());
        event.setEventType("ORDER_CREATED");
        event.setTimestamp(LocalDateTime.now());
        
        rabbitTemplate.convertAndSend("order.exchange", "order.created", event);
    }
    
    public void publishOrderUpdated(Order order) {
        OrderEvent event = new OrderEvent();
        event.setOrderId(order.getId());
        event.setUserId(order.getUserId());
        event.setEventType("ORDER_UPDATED");
        event.setTimestamp(LocalDateTime.now());
        
        rabbitTemplate.convertAndSend("order.exchange", "order.updated", event);
    }
}

// Consumer Service
@Component
public class OrderEventConsumer {
    
    private static final Logger logger = LoggerFactory.getLogger(OrderEventConsumer.class);
    
    @Autowired
    private NotificationService notificationService;
    
    @RabbitListener(queues = "order.created.queue")
    public void handleOrderCreated(OrderEvent event) {
        logger.info("Processing order created event: {}", event.getOrderId());
        
        try {
            // Send notification to user
            notificationService.sendOrderConfirmation(event.getUserId(), event.getOrderId());
            
            // Update inventory
            updateInventory(event);
            
        } catch (Exception e) {
            logger.error("Error processing order created event", e);
            throw new MessageProcessingException("Failed to process order created event", e);
        }
    }
    
    @RabbitListener(queues = "order.updated.queue")
    public void handleOrderUpdated(OrderEvent event) {
        logger.info("Processing order updated event: {}", event.getOrderId());
        
        try {
            // Send update notification
            notificationService.sendOrderUpdate(event.getUserId(), event.getOrderId());
            
        } catch (Exception e) {
            logger.error("Error processing order updated event", e);
            throw new MessageProcessingException("Failed to process order updated event", e);
        }
    }
    
    private void updateInventory(OrderEvent event) {
        // Implementation for inventory update
        logger.info("Updating inventory for order: {}", event.getOrderId());
    }
}
```

#### Configuration for Message Queues
```yaml
# RabbitMQ Configuration
spring:
  rabbitmq:
    host: localhost
    port: 5672
    username: guest
    password: guest
    virtual-host: /
    publisher-confirms: true
    publisher-returns: true
    template:
      retry:
        enabled: true
        initial-interval: 1000
        max-attempts: 3
        multiplier: 2
```

```java
@Configuration
@EnableRabbit
public class RabbitConfig {
    
    @Bean
    public TopicExchange orderExchange() {
        return new TopicExchange("order.exchange");
    }
    
    @Bean
    public Queue orderCreatedQueue() {
        return QueueBuilder.durable("order.created.queue").build();
    }
    
    @Bean
    public Queue orderUpdatedQueue() {
        return QueueBuilder.durable("order.updated.queue").build();
    }
    
    @Bean
    public Binding orderCreatedBinding() {
        return BindingBuilder.bind(orderCreatedQueue())
            .to(orderExchange())
            .with("order.created");
    }
    
    @Bean
    public Binding orderUpdatedBinding() {
        return BindingBuilder.bind(orderUpdatedQueue())
            .to(orderExchange())
            .with("order.updated");
    }
    
    @Bean
    public RabbitTemplate rabbitTemplate(ConnectionFactory connectionFactory) {
        RabbitTemplate template = new RabbitTemplate(connectionFactory);
        template.setMessageConverter(new Jackson2JsonMessageConverter());
        template.setConfirmCallback((correlationData, ack, cause) -> {
            if (ack) {
                logger.info("Message sent successfully");
            } else {
                logger.error("Message failed to send: {}", cause);
            }
        });
        return template;
    }
}
```

### 3. Service-to-Service Authentication

#### JWT Token Propagation
```java
@Component
public class JwtTokenInterceptor implements ClientHttpRequestInterceptor {
    
    @Override
    public ClientHttpResponse intercept(
            HttpRequest request, 
            byte[] body, 
            ClientHttpRequestExecution execution) throws IOException {
        
        // Get current JWT token from security context
        String token = getCurrentJwtToken();
        
        if (token != null) {
            request.getHeaders().add("Authorization", "Bearer " + token);
        }
        
        return execution.execute(request, body);
    }
    
    private String getCurrentJwtToken() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof JwtAuthenticationToken) {
            return ((JwtAuthenticationToken) authentication).getToken().getTokenValue();
        }
        return null;
    }
}

@Configuration
public class SecurityConfig {
    
    @Bean
    public RestTemplate secureRestTemplate() {
        RestTemplate restTemplate = new RestTemplate();
        restTemplate.getInterceptors().add(new JwtTokenInterceptor());
        return restTemplate;
    }
}
```

#### Service-to-Service API Key Authentication
```java
@Component
public class ApiKeyInterceptor implements ClientHttpRequestInterceptor {
    
    @Value("${app.api-key}")
    private String apiKey;
    
    @Override
    public ClientHttpResponse intercept(
            HttpRequest request, 
            byte[] body, 
            ClientHttpRequestExecution execution) throws IOException {
        
        request.getHeaders().add("X-API-Key", apiKey);
        request.getHeaders().add("X-Service-Name", "order-service");
        
        return execution.execute(request, body);
    }
}
```

### 4. Circuit Breaker Pattern

#### Using Resilience4j
```java
@Component
public class ProductServiceClient {
    
    private final RestTemplate restTemplate;
    private final CircuitBreaker circuitBreaker;
    
    public ProductServiceClient(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
        this.circuitBreaker = CircuitBreaker.ofDefaults("productService");
    }
    
    public Product getProduct(Long productId) {
        return circuitBreaker.executeSupplier(() -> {
            String url = "http://product-service/products/" + productId;
            return restTemplate.getForObject(url, Product.class);
        });
    }
    
    public List<Product> getProductsWithFallback(List<Long> productIds) {
        return circuitBreaker.executeSupplier(() -> {
            // Primary call
            return getProductsFromService(productIds);
        }).recover(throwable -> {
            // Fallback implementation
            return getProductsFromCache(productIds);
        });
    }
    
    private List<Product> getProductsFromService(List<Long> productIds) {
        String url = "http://product-service/products/batch";
        HttpEntity<List<Long>> request = new HttpEntity<>(productIds);
        
        ResponseEntity<List<Product>> response = restTemplate.exchange(
            url, HttpMethod.POST, request, 
            new ParameterizedTypeReference<List<Product>>() {}
        );
        
        return response.getBody();
    }
    
    private List<Product> getProductsFromCache(List<Long> productIds) {
        // Fallback implementation using cache
        return productIds.stream()
            .map(this::getProductFromCache)
            .filter(Objects::nonNull)
            .collect(Collectors.toList());
    }
    
    private Product getProductFromCache(Long productId) {
        // Implementation for cache lookup
        return null;
    }
}
```

### 5. Retry Mechanism

```java
@Service
public class UserServiceClient {
    
    @Autowired
    private RestTemplate restTemplate;
    
    @Retryable(
        value = {ResourceAccessException.class, HttpServerErrorException.class},
        maxAttempts = 3,
        backoff = @Backoff(delay = 1000, multiplier = 2)
    )
    public User getUser(Long userId) {
        String url = "http://user-service/users/" + userId;
        
        try {
            ResponseEntity<User> response = restTemplate.getForEntity(url, User.class);
            return response.getBody();
        } catch (HttpClientErrorException e) {
            if (e.getStatusCode() == HttpStatus.NOT_FOUND) {
                throw new UserNotFoundException("User not found: " + userId);
            }
            throw e;
        }
    }
    
    @Recover
    public User recover(Exception e, Long userId) {
        // Fallback method called after max attempts
        User fallbackUser = new User();
        fallbackUser.setId(userId);
        fallbackUser.setName("Unknown User");
        return fallbackUser;
    }
}
```

### 6. Load Balancing Strategies

```java
@Configuration
public class LoadBalancerConfig {
    
    @Bean
    @LoadBalanced
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
    
    // Custom load balancer configuration
    @Bean
    public ReactorLoadBalancer<ServiceInstance> randomLoadBalancer(
            Environment environment,
            LoadBalancerClientFactory loadBalancerClientFactory) {
        
        String name = environment.getProperty(LoadBalancerClientFactory.PROPERTY_NAME);
        return new RandomLoadBalancer(
            loadBalancerClientFactory.getLazyProvider(name, ServiceInstanceListSupplier.class),
            name
        );
    }
}

// Custom load balancer implementation
public class WeightedLoadBalancer implements ReactorServiceInstanceLoadBalancer {
    
    private final String serviceId;
    private final ObjectProvider<ServiceInstanceListSupplier> serviceInstanceListSupplierProvider;
    
    public WeightedLoadBalancer(ObjectProvider<ServiceInstanceListSupplier> serviceInstanceListSupplierProvider,
                               String serviceId) {
        this.serviceId = serviceId;
        this.serviceInstanceListSupplierProvider = serviceInstanceListSupplierProvider;
    }
    
    @Override
    public Mono<Response<ServiceInstance>> choose(Request request) {
        ServiceInstanceListSupplier supplier = serviceInstanceListSupplierProvider
            .getIfAvailable(NoopServiceInstanceListSupplier::new);
        
        return supplier.get(request).next()
            .map(serviceInstances -> processInstanceResponse(serviceInstances, request));
    }
    
    private Response<ServiceInstance> processInstanceResponse(
            List<ServiceInstance> serviceInstances, Request request) {
        
        if (serviceInstances.isEmpty()) {
            return new EmptyResponse();
        }
        
        // Weighted selection logic
        ServiceInstance selectedInstance = selectByWeight(serviceInstances);
        
        return new DefaultResponse(selectedInstance);
    }
    
    private ServiceInstance selectByWeight(List<ServiceInstance> instances) {
        // Implementation for weighted selection
        Map<ServiceInstance, Integer> weights = new HashMap<>();
        
        for (ServiceInstance instance : instances) {
            String weightStr = instance.getMetadata().get("weight");
            int weight = weightStr != null ? Integer.parseInt(weightStr) : 1;
            weights.put(instance, weight);
        }
        
        int totalWeight = weights.values().stream().mapToInt(Integer::intValue).sum();
        int random = new Random().nextInt(totalWeight);
        
        int current = 0;
        for (Map.Entry<ServiceInstance, Integer> entry : weights.entrySet()) {
            current += entry.getValue();
            if (random < current) {
                return entry.getKey();
            }
        }
        
        return instances.get(0); // Fallback
    }
}
```

### 7. Monitoring and Observability

```java
@Component
public class ServiceMetrics {
    
    private final MeterRegistry meterRegistry;
    private final Counter successfulCalls;
    private final Counter failedCalls;
    private final Timer responseTime;
    
    public ServiceMetrics(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
        this.successfulCalls = Counter.builder("service.calls.success")
            .description("Number of successful service calls")
            .register(meterRegistry);
        this.failedCalls = Counter.builder("service.calls.failed")
            .description("Number of failed service calls")
            .register(meterRegistry);
        this.responseTime = Timer.builder("service.calls.duration")
            .description("Service call duration")
            .register(meterRegistry);
    }
    
    public void recordSuccess(String serviceName) {
        successfulCalls.increment(Tags.of("service", serviceName));
    }
    
    public void recordFailure(String serviceName, String errorType) {
        failedCalls.increment(Tags.of("service", serviceName, "error", errorType));
    }
    
    public void recordDuration(String serviceName, Duration duration) {
        responseTime.record(duration, Tags.of("service", serviceName));
    }
}

@Component
public class ServiceCallInterceptor implements ClientHttpRequestInterceptor {
    
    @Autowired
    private ServiceMetrics serviceMetrics;
    
    @Override
    public ClientHttpResponse intercept(
            HttpRequest request, 
            byte[] body, 
            ClientHttpRequestExecution execution) throws IOException {
        
        String serviceName = extractServiceName(request.getURI());
        Instant start = Instant.now();
        
        try {
            ClientHttpResponse response = execution.execute(request, body);
            
            Duration duration = Duration.between(start, Instant.now());
            serviceMetrics.recordDuration(serviceName, duration);
            
            if (response.getStatusCode().is2xxSuccessful()) {
                serviceMetrics.recordSuccess(serviceName);
            } else {
                serviceMetrics.recordFailure(serviceName, response.getStatusCode().toString());
            }
            
            return response;
        } catch (Exception e) {
            Duration duration = Duration.between(start, Instant.now());
            serviceMetrics.recordDuration(serviceName, duration);
            serviceMetrics.recordFailure(serviceName, e.getClass().getSimpleName());
            throw e;
        }
    }
    
    private String extractServiceName(URI uri) {
        String host = uri.getHost();
        return host != null ? host : "unknown";
    }
}
```# Service Discovery in Java: Eureka vs Consul

## Overview

Service discovery is a critical component in microservices architecture that enables services to locate and communicate with each other dynamically. This document explores two popular service discovery solutions: Netflix Eureka and HashiCorp Consul, focusing on their implementation in Java applications.

## What is Service Discovery?

Service discovery is the process of automatically detecting and registering services in a distributed system. It eliminates the need for hardcoded service locations and enables dynamic scaling, load balancing, and fault tolerance.

### Key Benefits
- **Dynamic service registration and deregistration**
- **Load balancing and failover**
- **Health checking and monitoring**
- **Configuration management**
- **Decoupling of service dependencies**

## Netflix Eureka

### Architecture Overview

Eureka follows a client-server architecture with three main components:

1. **Eureka Server (Service Registry)**
   - Stores information about all client service instances
   - Provides REST API for service registration and discovery
   - Maintains a registry of available services

2. **Eureka Client (Service Instance)**
   - Registers itself with the Eureka Server
   - Periodically sends heartbeats to maintain registration
   - Fetches registry information from the server

3. **Application Client**
   - Consumes services by querying the Eureka Server
   - Implements client-side load balancing

### Key Features

#### Service Registration
- **Automatic registration** when service starts
- **Heartbeat mechanism** for health monitoring (default: 30 seconds)
- **Graceful deregistration** when service shuts down
- **Self-preservation mode** to handle network partitions

#### Service Discovery
- **REST-based API** for service lookup
- **Client-side caching** of service registry
- **Periodic registry updates** (default: 30 seconds)
- **Zone-aware routing** for multi-region deployments

#### High Availability
- **Multi-instance deployment** with peer-to-peer replication
- **AP (Availability and Partition tolerance)** in CAP theorem
- **Self-preservation mode** prevents mass service deregistration

### Java Implementation

#### Maven Dependencies
```xml
<!-- Eureka Server -->
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-netflix-eureka-server</artifactId>
</dependency>

<!-- Eureka Client -->
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-netflix-eureka-client</artifactId>
</dependency>

<!-- For inter-service communication -->
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-openfeign</artifactId>
</dependency>

<!-- Load balancer -->
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-loadbalancer</artifactId>
</dependency>
```

#### Configuration Examples

**Eureka Server Configuration (application.yml)**
```yaml
server:
  port: 8761

eureka:
  instance:
    hostname: localhost
  client:
    register-with-eureka: false
    fetch-registry: false
    service-url:
      defaultZone: http://${eureka.instance.hostname}:${server.port}/eureka/
  server:
    enable-self-preservation: false
    eviction-interval-timer-in-ms: 5000
```

**Eureka Client Configuration (application.yml)**
```yaml
spring:
  application:
    name: user-service

server:
  port: 8080

eureka:
  client:
    service-url:
      defaultZone: http://localhost:8761/eureka/
    fetch-registry: true
    register-with-eureka: true
    registry-fetch-interval-seconds: 30
  instance:
    lease-renewal-interval-in-seconds: 30
    lease-expiration-duration-in-seconds: 90
    prefer-ip-address: true
    instance-id: ${spring.application.name}:${spring.application.instance_id:${random.value}}

management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics
  endpoint:
    health:
      show-details: always
```

#### Complete Java Code Examples

**1. Eureka Server Application**
```java
@SpringBootApplication
@EnableEurekaServer
public class EurekaServerApplication {
    public static void main(String[] args) {
        SpringApplication.run(EurekaServerApplication.class, args);
    }
}
```

**2. User Service (Producer)**
```java
@SpringBootApplication
@EnableEurekaClient
public class UserServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(UserServiceApplication.class, args);
    }
}

@RestController
@RequestMapping("/users")
public class UserController {
    
    @Autowired
    private UserService userService;
    
    @GetMapping("/{id}")
    public ResponseEntity<User> getUser(@PathVariable Long id) {
        User user = userService.findById(id);
        return ResponseEntity.ok(user);
    }
    
    @GetMapping
    public ResponseEntity<List<User>> getAllUsers() {
        List<User> users = userService.findAll();
        return ResponseEntity.ok(users);
    }
    
    @PostMapping
    public ResponseEntity<User> createUser(@RequestBody User user) {
        User createdUser = userService.save(user);
        return ResponseEntity.status(HttpStatus.CREATED).body(createdUser);
    }
}

@Service
public class UserService {
    
    @Autowired
    private UserRepository userRepository;
    
    public User findById(Long id) {
        return userRepository.findById(id)
            .orElseThrow(() -> new UserNotFoundException("User not found with id: " + id));
    }
    
    public List<User> findAll() {
        return userRepository.findAll();
    }
    
    public User save(User user) {
        return userRepository.save(user);
    }
}
```

**3. Order Service (Consumer) - Using RestTemplate**
```java
@SpringBootApplication
@EnableEurekaClient
public class OrderServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(OrderServiceApplication.class, args);
    }
    
    @Bean
    @LoadBalanced
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}

@RestController
@RequestMapping("/orders")
public class OrderController {
    
    @Autowired
    private OrderService orderService;
    
    @GetMapping("/{id}")
    public ResponseEntity<Order> getOrder(@PathVariable Long id) {
        Order order = orderService.findById(id);
        return ResponseEntity.ok(order);
    }
    
    @PostMapping
    public ResponseEntity<Order> createOrder(@RequestBody CreateOrderRequest request) {
        Order order = orderService.createOrder(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(order);
    }
}

@Service
public class OrderService {
    
    @Autowired
    private RestTemplate restTemplate;
    
    @Autowired
    private OrderRepository orderRepository;
    
    public Order createOrder(CreateOrderRequest request) {
        // Fetch user details from User Service
        User user = getUserFromUserService(request.getUserId());
        
        if (user == null) {
            throw new UserNotFoundException("User not found");
        }
        
        Order order = new Order();
        order.setUserId(user.getId());
        order.setUserName(user.getName());
        order.setProductId(request.getProductId());
        order.setQuantity(request.getQuantity());
        order.setStatus(OrderStatus.PENDING);
        
        return orderRepository.save(order);
    }
    
    private User getUserFromUserService(Long userId) {
        try {
            // Using service name registered with Eureka
            String url = "http://user-service/users/" + userId;
            return restTemplate.getForObject(url, User.class);
        } catch (Exception e) {
            throw new ServiceCommunicationException("Failed to fetch user details", e);
        }
    }
    
    public Order findById(Long id) {
        return orderRepository.findById(id)
            .orElseThrow(() -> new OrderNotFoundException("Order not found"));
    }
}
```

**4. Order Service (Consumer) - Using Feign Client**
```java
@SpringBootApplication
@EnableEurekaClient
@EnableFeignClients
public class OrderServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(OrderServiceApplication.class, args);
    }
}

@FeignClient(name = "user-service", fallback = UserServiceFallback.class)
public interface UserServiceClient {
    
    @GetMapping("/users/{id}")
    User getUser(@PathVariable("id") Long id);
    
    @GetMapping("/users")
    List<User> getAllUsers();
    
    @PostMapping("/users")
    User createUser(@RequestBody User user);
}

@Component
public class UserServiceFallback implements UserServiceClient {
    
    @Override
    public User getUser(Long id) {
        // Fallback implementation
        User fallbackUser = new User();
        fallbackUser.setId(id);
        fallbackUser.setName("Unknown User");
        fallbackUser.setEmail("unknown@example.com");
        return fallbackUser;
    }
    
    @Override
    public List<User> getAllUsers() {
        return Collections.emptyList();
    }
    
    @Override
    public User createUser(User user) {
        throw new ServiceUnavailableException("User service is currently unavailable");
    }
}

@Service
public class OrderService {
    
    @Autowired
    private UserServiceClient userServiceClient;
    
    @Autowired
    private OrderRepository orderRepository;
    
    public Order createOrder(CreateOrderRequest request) {
        // Fetch user details using Feign client
        User user = userServiceClient.getUser(request.getUserId());
        
        Order order = new Order();
        order.setUserId(user.getId());
        order.setUserName(user.getName());
        order.setProductId(request.getProductId());
        order.setQuantity(request.getQuantity());
        order.setStatus(OrderStatus.PENDING);
        
        return orderRepository.save(order);
    }
}
```

**5. Service Discovery Programmatic Access**
```java
@Service
public class ServiceDiscoveryService {
    
    @Autowired
    private DiscoveryClient discoveryClient;
    
    public List<String> getServiceInstances(String serviceName) {
        return discoveryClient.getInstances(serviceName)
            .stream()
            .map(instance -> instance.getUri().toString())
            .collect(Collectors.toList());
    }
    
    public List<String> getAllServices() {
        return discoveryClient.getServices();
    }
    
    public ServiceInstance getServiceInstance(String serviceName) {
        List<ServiceInstance> instances = discoveryClient.getInstances(serviceName);
        if (instances.isEmpty()) {
            throw new ServiceNotFoundException("No instances found for service: " + serviceName);
        }
        // Simple load balancing - return first available instance
        return instances.get(0);
    }
}

@RestController
@RequestMapping("/discovery")
public class ServiceDiscoveryController {
    
    @Autowired
    private ServiceDiscoveryService discoveryService;
    
    @GetMapping("/services")
    public ResponseEntity<List<String>> getAllServices() {
        List<String> services = discoveryService.getAllServices();
        return ResponseEntity.ok(services);
    }
    
    @GetMapping("/services/{serviceName}/instances")
    public ResponseEntity<List<String>> getServiceInstances(@PathVariable String serviceName) {
        List<String> instances = discoveryService.getServiceInstances(serviceName);
        return ResponseEntity.ok(instances);
    }
}
```

**6. Custom Health Indicator**
```java
@Component
public class CustomHealthIndicator implements HealthIndicator {
    
    @Autowired
    private UserRepository userRepository;
    
    @Override
    public Health health() {
        try {
            long userCount = userRepository.count();
            if (userCount > 0) {
                return Health.up()
                    .withDetail("userCount", userCount)
                    .withDetail("status", "Database is accessible")
                    .build();
            } else {
                return Health.down()
                    .withDetail("userCount", userCount)
                    .withDetail("status", "No users found")
                    .build();
            }
        } catch (Exception e) {
            return Health.down()
                .withDetail("error", e.getMessage())
                .withDetail("status", "Database connection failed")
                .build();
        }
    }
}
```

### Advantages
- **Simple setup and configuration**
- **Excellent Spring Boot integration**
- **Mature and battle-tested** (used extensively by Netflix)
- **Built-in dashboard** for monitoring
- **No external dependencies**

### Disadvantages
- **Limited to Java ecosystem** (primarily Spring Boot)
- **No built-in security features**
- **Limited configuration management**
- **No multi-datacenter support** out of the box
- **Performance issues** with large number of services

## HashiCorp Consul

### Architecture Overview

Consul is a distributed service mesh solution with multiple components:

1. **Consul Agent**
   - Runs on every node in the cluster
   - Maintains local service registry
   - Performs health checks
   - Forwards queries to Consul servers

2. **Consul Server**
   - Maintains global service registry
   - Participates in consensus protocol (Raft)
   - Handles service discovery queries
   - Manages configuration data

3. **Consul Client**
   - Lightweight agent for service registration
   - Forwards requests to Consul servers
   - Caches service discovery data

### Key Features

#### Service Discovery
- **DNS-based service discovery**
- **HTTP API** for programmatic access
- **Service mesh capabilities** with Consul Connect
- **Multi-datacenter support** with WAN federation

#### Health Checking
- **Multiple health check types**: HTTP, TCP, script-based, TTL
- **Distributed health checking**
- **Configurable check intervals**
- **Health check de-registration**

#### Configuration Management
- **Key-Value store** for configuration data
- **Hierarchical configuration**
- **Configuration watches** for real-time updates
- **ACL system** for security

#### Security
- **ACL (Access Control Lists)** for fine-grained permissions
- **TLS encryption** for all communications
- **Service-to-service encryption** with Consul Connect
- **Intention-based access control**

### Java Implementation

#### Maven Dependencies
```xml
<!-- Consul Discovery -->
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-consul-discovery</artifactId>
</dependency>

<!-- Consul Config -->
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-consul-config</artifactId>
</dependency>

<!-- For inter-service communication -->
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-openfeign</artifactId>
</dependency>

<!-- Load balancer -->
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-loadbalancer</artifactId>
</dependency>
```

#### Configuration Examples

**Consul Client Configuration (application.yml)**
```yaml
spring:
  application:
    name: user-service
  cloud:
    consul:
      host: localhost
      port: 8500
      discovery:
        enabled: true
        register: true
        service-name: ${spring.application.name}
        health-check-interval: 15s
        health-check-critical-timeout: 30s
        health-check-path: /actuator/health
        instance-id: ${spring.application.name}:${spring.cloud.client.ip-address}:${server.port}
        prefer-ip-address: true
        tags:
          - version=1.0
          - environment=production
          - team=backend
      config:
        enabled: true
        format: yaml
        data-key: configuration
        watch:
          enabled: true

server:
  port: 8080

management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics,consul
  endpoint:
    health:
      show-details: always
```

**Health Check Configuration**
```yaml
spring:
  cloud:
    consul:
      discovery:
        health-check-url: http://localhost:8080/actuator/health
        health-check-interval: 10s
        health-check-timeout: 5s
        health-check-critical-timeout: 30s
        health-check-tls-skip-verify: true
```

#### Complete Java Code Examples

**1. User Service with Consul**
```java
@SpringBootApplication
@EnableDiscoveryClient
public class UserServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(UserServiceApplication.class, args);
    }
}

@RestController
@RequestMapping("/users")
public class UserController {
    
    @Autowired
    private UserService userService;
    
    @Autowired
    private ConsulTemplate consulTemplate;
    
    @GetMapping("/{id}")
    public ResponseEntity<User> getUser(@PathVariable Long id) {
        User user = userService.findById(id);
        return ResponseEntity.ok(user);
    }
    
    @GetMapping
    public ResponseEntity<List<User>> getAllUsers() {
        List<User> users = userService.findAll();
        return ResponseEntity.ok(users);
    }
    
    @PostMapping
    public ResponseEntity<User> createUser(@RequestBody User user) {
        User createdUser = userService.save(user);
        return ResponseEntity.status(HttpStatus.CREATED).body(createdUser);
    }
    
    @GetMapping("/config/{key}")
    public ResponseEntity<String> getConfig(@PathVariable String key) {
        String value = consulTemplate.getKVValue(key);
        return ResponseEntity.ok(value);
    }
}

@Service
public class UserService {
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private ConsulTemplate consulTemplate;
    
    public User findById(Long id) {
        // Log service call for monitoring
        consulTemplate.putKVValue("metrics/user-service/calls", 
            String.valueOf(System.currentTimeMillis()));
        
        return userRepository.findById(id)
            .orElseThrow(() -> new UserNotFoundException("User not found with id: " + id));
    }
    
    public List<User> findAll() {
        return userRepository.findAll();
    }
    
    public User save(User user) {
        return userRepository.save(user);
    }
}
```

**2. Order Service with Consul - Using RestTemplate**
```java
@SpringBootApplication
@EnableDiscoveryClient
public class OrderServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(OrderServiceApplication.class, args);
    }
    
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
    
    @Autowired
    private OrderRepository orderRepository;
    
    @Autowired
    private ConsulTemplate consulTemplate;
    
    public Order createOrder(CreateOrderRequest request) {
        // Get user service configuration from Consul
        String userServiceUrl = consulTemplate.getKVValue("services/user-service/url");
        
        // Fetch user details from User Service
        User user = getUserFromUserService(request.getUserId());
        
        if (user == null) {
            throw new UserNotFoundException("User not found");
        }
        
        Order order = new Order();
        order.setUserId(user.getId());
        order.setUserName(user.getName());
        order.setProductId(request.getProductId());
        order.setQuantity(request.getQuantity());
        order.setStatus(OrderStatus.PENDING);
        
        Order savedOrder = orderRepository.save(order);
        
        // Update metrics in Consul
        updateOrderMetrics();
        
        return savedOrder;
    }
    
    private User getUserFromUserService(Long userId) {
        try {
            // Using service name registered with Consul
            String url = "http://user-service/users/" + userId;
            return restTemplate.getForObject(url, User.class);
        } catch (Exception e) {
            throw new ServiceCommunicationException("Failed to fetch user details", e);
        }
    }
    
    private void updateOrderMetrics() {
        long orderCount = orderRepository.count();
        consulTemplate.putKVValue("metrics/order-service/total-orders", 
            String.valueOf(orderCount));
    }
}
```

**3. Order Service with Consul - Using Feign Client**
```java
@SpringBootApplication
@EnableDiscoveryClient
@EnableFeignClients
public class OrderServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(OrderServiceApplication.class, args);
    }
}

@FeignClient(name = "user-service", fallback = UserServiceFallback.class)
public interface UserServiceClient {
    
    @GetMapping("/users/{id}")
    User getUser(@PathVariable("id") Long id);
    
    @GetMapping("/users")
    List<User> getAllUsers();
    
    @PostMapping("/users")
    User createUser(@RequestBody User user);
    
    @GetMapping("/users/config/{key}")
    String getConfig(@PathVariable("key") String key);
}

@Component
public class UserServiceFallback implements UserServiceClient {
    
    @Override
    public User getUser(Long id) {
        User fallbackUser = new User();
        fallbackUser.setId(id);
        fallbackUser.setName("Unknown User");
        fallbackUser.setEmail("unknown@example.com");
        return fallbackUser;
    }
    
    @Override
    public List<User> getAllUsers() {
        return Collections.emptyList();
    }
    
    @Override
    public User createUser(User user) {
        throw new ServiceUnavailableException("User service is currently unavailable");
    }
    
    @Override
    public String getConfig(String key) {
        return "default-config-value";
    }
}
```

**4. Consul Service Discovery Programmatic Access**
```java
@Service
public class ConsulServiceDiscoveryService {
    
    @Autowired
    private DiscoveryClient discoveryClient;
    
    @Autowired
    private ConsulTemplate consulTemplate;
    
    public List<String> getHealthyServiceInstances(String serviceName) {
        return discoveryClient.getInstances(serviceName)
            .stream()
            .filter(instance -> isServiceHealthy(instance))
            .map(instance -> instance.getUri().toString())
            .collect(Collectors.toList());
    }
    
    public List<String> getAllServices() {
        return discoveryClient.getServices();
    }
    
    public ServiceInstance getServiceInstance(String serviceName) {
        List<ServiceInstance> instances = discoveryClient.getInstances(serviceName);
        if (instances.isEmpty()) {
            throw new ServiceNotFoundException("No instances found for service: " + serviceName);
        }
        
        // Load balancing with health check
        return instances.stream()
            .filter(this::isServiceHealthy)
            .findFirst()
            .orElseThrow(() -> new ServiceNotFoundException("No healthy instances found for service: " + serviceName));
    }
    
    private boolean isServiceHealthy(ServiceInstance instance) {
        // Custom health check logic
        try {
            String healthUrl = instance.getUri() + "/actuator/health";
            RestTemplate restTemplate = new RestTemplate();
            ResponseEntity<String> response = restTemplate.getForEntity(healthUrl, String.class);
            return response.getStatusCode() == HttpStatus.OK;
        } catch (Exception e) {
            return false;
        }
    }
    
    public void registerService(String serviceName, String serviceId, String address, int port) {
        consulTemplate.agentServiceRegister(serviceName, serviceId, address, port);
    }
    
    public void deregisterService(String serviceId) {
        consulTemplate.agentServiceDeregister(serviceId);
    }
}

@RestController
@RequestMapping("/consul-discovery")
public class ConsulServiceDiscoveryController {
    
    @Autowired
    private ConsulServiceDiscoveryService discoveryService;
    
    @GetMapping("/services")
    public ResponseEntity<List<String>> getAllServices() {
        List<String> services = discoveryService.getAllServices();
        return ResponseEntity.ok(services);
    }
    
    @GetMapping("/services/{serviceName}/instances")
    public ResponseEntity<List<String>> getServiceInstances(@PathVariable String serviceName) {
        List<String> instances = discoveryService.getHealthyServiceInstances(serviceName);
        return ResponseEntity.ok(instances);
    }
    
    @PostMapping("/services/{serviceName}/register")
    public ResponseEntity<String> registerService(
            @PathVariable String serviceName,
            @RequestParam String serviceId,
            @RequestParam String address,
            @RequestParam int port) {
        discoveryService.registerService(serviceName, serviceId, address, port);
        return ResponseEntity.ok("Service registered successfully");
    }
}
```

**5. Configuration Management with Consul**
```java
@Component
@ConfigurationProperties(prefix = "app")
@RefreshScope
public class AppConfig {
    
    private String name;
    private String version;
    private int maxConnections;
    private List<String> allowedOrigins;
    
    // Getters and setters
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    
    public String getVersion() { return version; }
    public void setVersion(String version) { this.version = version; }
    
    public int getMaxConnections() { return maxConnections; }
    public void setMaxConnections(int maxConnections) { this.maxConnections = maxConnections; }
    
    public List<String> getAllowedOrigins() { return allowedOrigins; }
    public void setAllowedOrigins(List<String> allowedOrigins) { this.allowedOrigins = allowedOrigins; }
}

@RestController
@RequestMapping("/config")
public class ConfigController {
    
    @Autowired
    private AppConfig appConfig;
    
    @Autowired
    private ConsulTemplate consulTemplate;
    
    @GetMapping("/current")
    public ResponseEntity<AppConfig> getCurrentConfig() {
        return ResponseEntity.ok(appConfig);
    }
    
    @GetMapping("/consul/{key}")
    public ResponseEntity<String> getConsulConfig(@PathVariable String key) {
        String value = consulTemplate.getKVValue(key);
        return ResponseEntity.ok(value);
    }
    
    @PutMapping("/consul/{key}")
    public ResponseEntity<String> setConsulConfig(@PathVariable String key, @RequestBody String value) {
        consulTemplate.putKVValue(key, value);
        return ResponseEntity.ok("Configuration updated");
    }
}
```

**6. Advanced Health Checks with Consul**
```java
@Component
public class ConsulHealthIndicator implements HealthIndicator {
    
    @Autowired
    private ConsulTemplate consulTemplate;
    
    @Autowired
    private UserRepository userRepository;
    
    @Override
    public Health health() {
        try {
            // Check database connectivity
            long userCount = userRepository.count();
            
            // Check Consul connectivity
            boolean consulHealthy = isConsulHealthy();
            
            // Check external dependencies
            boolean externalServiceHealthy = checkExternalServices();
            
            if (consulHealthy && externalServiceHealthy) {
                return Health.up()
                    .withDetail("userCount", userCount)
                    .withDetail("consulStatus", "UP")
                    .withDetail("externalServices", "UP")
                    .withDetail("timestamp", System.currentTimeMillis())
                    .build();
            } else {
                return Health.down()
                    .withDetail("consulStatus", consulHealthy ? "UP" : "DOWN")
                    .withDetail("externalServices", externalServiceHealthy ? "UP" : "DOWN")
                    .build();
            }
        } catch (Exception e) {
            return Health.down()
                .withDetail("error", e.getMessage())
                .withDetail("timestamp", System.currentTimeMillis())
                .build();
        }
    }
    
    private boolean isConsulHealthy() {
        try {
            consulTemplate.getKVValue("health-check");
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    
    private boolean checkExternalServices() {
        try {
            // Check if user-service is available
            RestTemplate restTemplate = new RestTemplate();
            String url = "http://user-service/actuator/health";
            ResponseEntity<String> response = restTemplate.getForEntity(url, String.class);
            return response.getStatusCode() == HttpStatus.OK;
        } catch (Exception e) {
            return false;
        }
    }
}

### Advantages
- **Language agnostic** (supports multiple programming languages)
- **Built-in security features** (ACLs, TLS)
- **Multi-datacenter support** out of the box
- **Comprehensive health checking**
- **Configuration management** capabilities
- **Service mesh features** with Consul Connect
- **DNS-based discovery**

### Disadvantages
- **Complex setup and configuration**
- **Requires external infrastructure**
- **Steeper learning curve**
- **Resource intensive** (requires more memory and CPU)
- **Operational complexity** for maintenance

## Comparison Matrix

| Aspect | Eureka | Consul |
|--------|--------|--------|
| **Language Support** | Java/JVM focused | Multi-language |
| **Setup Complexity** | Simple | Complex |
| **Health Checking** | Basic HTTP heartbeat | Comprehensive (HTTP, TCP, Script) |
| **Configuration Management** | Limited | Full KV store |
| **Security** | Basic | Advanced (ACL, TLS) |
| **Multi-datacenter** | Limited | Native support |
| **Service Mesh** | No | Yes (Consul Connect) |
| **DNS Support** | No | Yes |
| **Operational Overhead** | Low | High |
| **Community & Ecosystem** | Spring Cloud focused | Broader ecosystem |

## Performance Considerations

### Eureka Performance
- **Registry size**: Performance degrades with 1000+ services
- **Heartbeat frequency**: Balance between freshness and load
- **Client-side caching**: Reduces server load but affects consistency
- **Network partitions**: Self-preservation mode may cause stale data

### Consul Performance
- **Raft consensus**: Provides strong consistency but affects write performance
- **Health check frequency**: More frequent checks improve detection time
- **Agent distribution**: Local agents reduce network latency
- **Multi-datacenter**: WAN links can affect performance

## Best Practices

### Eureka Best Practices
- **Enable health checks** for accurate service status by implementing custom health indicators
- **Configure appropriate timeouts** for lease renewal and expiration to balance between responsiveness and stability
- **Use multiple Eureka servers** for high availability with peer-to-peer replication
- **Monitor registry size** and performance metrics to identify bottlenecks early
- **Implement graceful shutdown** for proper deregistration using @PreDestroy hooks
- **Use zone-aware routing** for multi-region deployments to reduce latency
- **Configure client-side caching** properly to balance between data freshness and performance
- **Implement retry logic** for service calls with exponential backoff
- **Use circuit breaker pattern** to prevent cascading failures
- **Monitor heartbeat intervals** and adjust based on network conditions

### Consul Best Practices
- **Use local agents** on each node for better performance and reduced network calls
- **Implement comprehensive health checks** using multiple check types (HTTP, TCP, script-based)
- **Secure with ACLs** and TLS in production environments for robust security
- **Monitor Consul cluster health** using built-in metrics and external monitoring tools
- **Plan for multi-datacenter** topology if needed with proper WAN federation
- **Use service mesh features** for advanced networking and security capabilities
- **Implement proper backup strategies** for the Consul data store
- **Use intentions** for service-to-service access control in service mesh
- **Monitor performance metrics** like leader election time and consensus latency
- **Implement proper disaster recovery** procedures for cluster failures

### Inter-Service Communication Best Practices
- **Use circuit breakers** to prevent cascading failures and improve system resilience
- **Implement retry mechanisms** with exponential backoff and jitter
- **Use timeouts** for all service calls to prevent resource exhaustion
- **Implement proper error handling** with meaningful error messages and logging
- **Use connection pooling** to optimize resource usage and performance
- **Implement request/response logging** for debugging and monitoring
- **Use correlation IDs** to trace requests across service boundaries
- **Implement rate limiting** to protect services from overload
- **Use asynchronous communication** where appropriate to improve scalability
- **Implement proper authentication** and authorization for service-to-service calls

## Migration Considerations

### From Eureka to Consul
- **Gradual migration** using dual registration
- **Update client code** to use Consul APIs
- **Implement proper health checks**
- **Configure security measures**
- **Plan for operational changes**

### From Consul to Eureka
- **Simplify health check logic**
- **Remove external dependencies**
- **Update monitoring and alerting**
- **Consider feature limitations**

## Conclusion

Both Eureka and Consul are excellent service discovery solutions, each with distinct advantages:

**Choose Eureka when:**
- Building Spring Boot microservices
- Need simple setup and maintenance
- Working within Java ecosystem
- Prioritizing ease of use over advanced features

**Choose Consul when:**
- Building polyglot microservices
- Need advanced security features
- Require multi-datacenter support
- Want service mesh capabilities
- Need comprehensive configuration management

The choice depends on your specific requirements, team expertise, and long-term architectural goals. Consider factors like operational complexity, security requirements, and ecosystem compatibility when making your decision.
