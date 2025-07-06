# Java Security Patterns and Principles

## Table of Contents
1. [Core Security Principles](#core-security-principles)
2. [Authentication Patterns](#authentication-patterns)
3. [Authorization Patterns](#authorization-patterns)
4. [Input Validation Patterns](#input-validation-patterns)
5. [Encryption Patterns](#encryption-patterns)
6. [Session Management Patterns](#session-management-patterns)
7. [CSRF Protection](#csrf-protection)
8. [Rate Limiting Pattern](#rate-limiting-pattern)
9. [SQL Injection Prevention](#sql-injection-prevention)
10. [Audit Logging Pattern](#audit-logging-pattern)
11. [Secure Configuration Pattern](#secure-configuration-pattern)
12. [Best Practices](#best-practices)

---

## Core Security Principles

### The CIA Triad
- **Confidentiality** - Protecting data from unauthorized disclosure
- **Integrity** - Ensuring data hasn't been tampered with
- **Availability** - Ensuring systems remain accessible

### Additional Security Principles
- **Authentication** - Verifying user identity
- **Authorization** - Controlling access to resources
- **Non-repudiation** - Preventing denial of actions
- **Least Privilege** - Granting minimum necessary permissions
- **Defense in Depth** - Multiple security layers
- **Fail Secure** - Systems should fail to a secure state
- **Separation of Duties** - Critical operations require multiple people

---

## Authentication Patterns

### 1. Basic Authentication

**Implementation:**
```java
@Configuration
@EnableWebSecurity
public class BasicAuthConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.httpBasic()
            .and()
            .authorizeHttpRequests(auth -> 
                auth.requestMatchers("/api/public/**").permitAll()
                    .requestMatchers("/api/**").authenticated()
            );
        return http.build();
    }
    
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withDefaultPasswordEncoder()
            .username("user")
            .password("password")
            .roles("USER")
            .build();
        return new InMemoryUserDetailsManager(user);
    }
}
```

**Security Considerations:**
- Always use HTTPS for Basic Authentication
- Credentials are base64 encoded, not encrypted
- Consider for internal APIs or development environments

### 2. JWT Token Authentication

**JWT Service Implementation:**
```java
@Service
public class JwtService {
    
    @Value("${jwt.secret}")
    private String secret;
    
    @Value("${jwt.expiration}")
    private Long expiration;
    
    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("authorities", userDetails.getAuthorities());
        return createToken(claims, userDetails.getUsername());
    }
    
    private String createToken(Map<String, Object> claims, String subject) {
        return Jwts.builder()
            .setClaims(claims)
            .setSubject(subject)
            .setIssuedAt(new Date(System.currentTimeMillis()))
            .setExpiration(new Date(System.currentTimeMillis() + expiration))
            .signWith(SignatureAlgorithm.HS512, secret)
            .compact();
    }
    
    public boolean validateToken(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return username.equals(userDetails.getUsername()) && !isTokenExpired(token);
    }
    
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }
    
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }
    
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }
    
    private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }
    
    private Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody();
    }
}
```

**JWT Filter:**
```java
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    
    @Autowired
    private JwtService jwtService;
    
    @Autowired
    private UserDetailsService userDetailsService;
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                  HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String username;
        
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        
        jwt = authHeader.substring(7);
        username = jwtService.extractUsername(jwt);
        
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            
            if (jwtService.validateToken(jwt, userDetails)) {
                UsernamePasswordAuthenticationToken authToken = 
                    new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities()
                    );
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        
        filterChain.doFilter(request, response);
    }
}
```

### 3. OAuth2 Implementation

**OAuth2 Configuration:**
```java
@Configuration
@EnableWebSecurity
public class OAuth2Config {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/login**", "/error**").permitAll()
                .anyRequest().authenticated()
            )
            .oauth2Login(oauth2 -> oauth2
                .loginPage("/login")
                .defaultSuccessUrl("/dashboard")
                .failureUrl("/login?error")
            );
        return http.build();
    }
    
    @Bean
    public ClientRegistrationRepository clientRegistrationRepository() {
        return new InMemoryClientRegistrationRepository(
            googleClientRegistration(),
            githubClientRegistration()
        );
    }
    
    private ClientRegistration googleClientRegistration() {
        return ClientRegistration.withRegistrationId("google")
            .clientId("${oauth2.google.client-id}")
            .clientSecret("${oauth2.google.client-secret}")
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("${oauth2.google.redirect-uri}")
            .scope("openid", "profile", "email")
            .authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
            .tokenUri("https://www.googleapis.com/oauth2/v4/token")
            .userInfoUri("https://www.googleapis.com/oauth2/v3/userinfo")
            .userNameAttributeName(IdTokenClaimNames.SUB)
            .jwkSetUri("https://www.googleapis.com/oauth2/v3/certs")
            .clientName("Google")
            .build();
    }
}
```

---

## Authorization Patterns

### 1. Role-Based Access Control (RBAC)

**Controller Level Security:**
```java
@RestController
@RequestMapping("/api/admin")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {
    
    @GetMapping("/users")
    public List<User> getAllUsers() {
        return userService.getAllUsers();
    }
    
    @DeleteMapping("/users/{id}")
    @PreAuthorize("hasRole('ADMIN') and hasAuthority('DELETE_USER')")
    public ResponseEntity<Void> deleteUser(@PathVariable Long id) {
        userService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }
}
```

**Method Level Security:**
```java
@Service
public class UserService {
    
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public User getUserProfile(Long userId) {
        return userRepository.findById(userId)
            .orElseThrow(() -> new UserNotFoundException("User not found"));
    }
    
    @PreAuthorize("hasRole('ADMIN') or (hasRole('USER') and #userId == authentication.principal.id)")
    public User updateUser(Long userId, User userDetails) {
        User existingUser = getUserProfile(userId);
        // Update logic
        return userRepository.save(existingUser);
    }
    
    @PostAuthorize("hasRole('ADMIN') or returnObject.id == authentication.principal.id")
    public User getUserById(Long id) {
        return userRepository.findById(id)
            .orElseThrow(() -> new UserNotFoundException("User not found"));
    }
}
```

### 2. Attribute-Based Access Control (ABAC)

**Custom Permission Evaluator:**
```java
@Component
public class CustomPermissionEvaluator implements PermissionEvaluator {
    
    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
        if (authentication == null || targetDomainObject == null) {
            return false;
        }
        
        String username = authentication.getName();
        String permissionString = permission.toString();
        
        if (targetDomainObject instanceof User) {
            return hasUserPermission(username, (User) targetDomainObject, permissionString);
        } else if (targetDomainObject instanceof Document) {
            return hasDocumentPermission(username, (Document) targetDomainObject, permissionString);
        }
        
        return false;
    }
    
    private boolean hasUserPermission(String username, User user, String permission) {
        switch (permission) {
            case "READ":
                return user.getUsername().equals(username) || isAdmin(username);
            case "WRITE":
                return user.getUsername().equals(username) || isAdmin(username);
            case "DELETE":
                return isAdmin(username);
            default:
                return false;
        }
    }
    
    private boolean hasDocumentPermission(String username, Document document, String permission) {
        switch (permission) {
            case "READ":
                return document.getOwner().equals(username) || 
                       document.getReadPermissions().contains(username) || 
                       isAdmin(username);
            case "WRITE":
                return document.getOwner().equals(username) || 
                       document.getWritePermissions().contains(username) || 
                       isAdmin(username);
            case "DELETE":
                return document.getOwner().equals(username) || isAdmin(username);
            default:
                return false;
        }
    }
    
    private boolean isAdmin(String username) {
        // Implementation to check if user has admin role
        return userService.hasRole(username, "ADMIN");
    }
    
    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission) {
        // Implementation for checking permissions by ID and type
        return false;
    }
}
```

**Usage in Service:**
```java
@Service
public class DocumentService {
    
    @PreAuthorize("hasPermission(#document, 'READ')")
    public Document getDocument(Document document) {
        return document;
    }
    
    @PreAuthorize("hasPermission(#document, 'WRITE')")
    public Document updateDocument(Document document) {
        return documentRepository.save(document);
    }
    
    @PreAuthorize("hasPermission(#document, 'DELETE')")
    public void deleteDocument(Document document) {
        documentRepository.delete(document);
    }
}
```

---

## Input Validation Patterns

### 1. Bean Validation

**Entity Validation:**
```java
@Entity
@Table(name = "users")
public class User {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    @Pattern(regexp = "^[a-zA-Z0-9_]+$", message = "Username can only contain letters, numbers, and underscores")
    private String username;
    
    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    private String email;
    
    @NotBlank(message = "Password is required")
    @Size(min = 8, message = "Password must be at least 8 characters")
    @Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]", 
             message = "Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character")
    private String password;
    
    @Past(message = "Birth date must be in the past")
    private LocalDate birthDate;
    
    @Valid
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<Address> addresses;
    
    // Constructors, getters, and setters
}
```

**Custom Validation Annotations:**
```java
@Documented
@Constraint(validatedBy = UniqueUsernameValidator.class)
@Target({ElementType.FIELD})
@Retention(RetentionPolicy.RUNTIME)
public @interface UniqueUsername {
    String message() default "Username already exists";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};
}

@Component
public class UniqueUsernameValidator implements ConstraintValidator<UniqueUsername, String> {
    
    @Autowired
    private UserRepository userRepository;
    
    @Override
    public boolean isValid(String username, ConstraintValidatorContext context) {
        if (username == null) {
            return true; // Let @NotBlank handle null validation
        }
        return !userRepository.existsByUsername(username);
    }
}
```

### 2. Input Sanitization

**XSS Protection:**
```java
@Component
public class InputSanitizer {
    
    private static final String[] XSS_PATTERNS = {
        "<script", "</script>", "javascript:", "onload=", "onerror=", 
        "onclick=", "onmouseover=", "onfocus=", "onblur=", "onchange=",
        "onsubmit=", "onkeydown=", "onkeypress=", "onkeyup=", "onselect="
    };
    
    private static final String[] SQL_INJECTION_PATTERNS = {
        "'", "\"", ";", "--", "/*", "*/", "xp_", "sp_", "union", "select", 
        "insert", "delete", "update", "create", "drop", "exec", "execute"
    };
    
    public String sanitizeForXSS(String input) {
        if (input == null) return null;
        
        String sanitized = input.toLowerCase();
        for (String pattern : XSS_PATTERNS) {
            if (sanitized.contains(pattern)) {
                throw new SecurityException("Potentially dangerous XSS content detected");
            }
        }
        
        return StringEscapeUtils.escapeHtml4(input);
    }
    
    public String sanitizeForSQL(String input) {
        if (input == null) return null;
        
        String sanitized = input.toLowerCase();
        for (String pattern : SQL_INJECTION_PATTERNS) {
            if (sanitized.contains(pattern)) {
                throw new SecurityException("Potentially dangerous SQL injection content detected");
            }
        }
        
        return input.trim();
    }
    
    public String sanitizeFileName(String fileName) {
        if (fileName == null) return null;
        
        // Remove path traversal attempts
        String sanitized = fileName.replaceAll("\\.\\.", "");
        sanitized = sanitized.replaceAll("[/\\\\]", "");
        
        // Remove potentially dangerous characters
        sanitized = sanitized.replaceAll("[<>:\"|?*]", "");
        
        return sanitized;
    }
}
```

**Global Exception Handler:**
```java
@ControllerAdvice
public class ValidationExceptionHandler {
    
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, String>> handleValidationExceptions(
            MethodArgumentNotValidException ex) {
        
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach((error) -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });
        
        return new ResponseEntity<>(errors, HttpStatus.BAD_REQUEST);
    }
    
    @ExceptionHandler(SecurityException.class)
    public ResponseEntity<String> handleSecurityException(SecurityException ex) {
        return new ResponseEntity<>("Security violation: " + ex.getMessage(), 
                                  HttpStatus.BAD_REQUEST);
    }
}
```

---

## Encryption Patterns

### 1. AES Encryption

**Symmetric Encryption Service:**
```java
@Service
public class EncryptionService {
    
    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int IV_LENGTH = 12;
    private static final int TAG_LENGTH = 16;
    
    @Value("${encryption.key}")
    private String encryptionKey;
    
    public String encrypt(String plainText) throws Exception {
        SecretKeySpec secretKey = new SecretKeySpec(
            encryptionKey.getBytes(StandardCharsets.UTF_8), "AES"
        );
        
        byte[] iv = new byte[IV_LENGTH];
        SecureRandom.getInstanceStrong().nextBytes(iv);
        
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        
        byte[] encrypted = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
        
        // Combine IV and encrypted data
        ByteBuffer buffer = ByteBuffer.allocate(iv.length + encrypted.length);
        buffer.put(iv);
        buffer.put(encrypted);
        
        return Base64.getEncoder().encodeToString(buffer.array());
    }
    
    public String decrypt(String encryptedText) throws Exception {
        byte[] decodedData = Base64.getDecoder().decode(encryptedText);
        
        // Extract IV and encrypted data
        ByteBuffer buffer = ByteBuffer.wrap(decodedData);
        byte[] iv = new byte[IV_LENGTH];
        buffer.get(iv);
        byte[] encrypted = new byte[buffer.remaining()];
        buffer.get(encrypted);
        
        SecretKeySpec secretKey = new SecretKeySpec(
            encryptionKey.getBytes(StandardCharsets.UTF_8), "AES"
        );
        
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH * 8, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
        
        byte[] decrypted = cipher.doFinal(encrypted);
        return new String(decrypted, StandardCharsets.UTF_8);
    }
}
```

### 2. Password Hashing

**BCrypt Password Service:**
```java
@Service
public class PasswordService {
    
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
    
    public String hashPassword(String password) {
        return encoder.encode(password);
    }
    
    public boolean verifyPassword(String password, String hashedPassword) {
        return encoder.matches(password, hashedPassword);
    }
    
    public boolean needsRehash(String hashedPassword) {
        return !hashedPassword.startsWith("$2a$12$");
    }
}
```

### 3. Digital Signatures

**Digital Signature Service:**
```java
@Service
public class DigitalSignatureService {
    
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final String KEY_ALGORITHM = "RSA";
    private static final int KEY_SIZE = 2048;
    
    public KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        keyPairGenerator.initialize(KEY_SIZE);
        return keyPairGenerator.generateKeyPair();
    }
    
    public String sign(String data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateKey);
        signature.update(data.getBytes(StandardCharsets.UTF_8));
        
        byte[] signatureBytes = signature.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }
    
    public boolean verify(String data, String signatureString, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initVerify(publicKey);
        signature.update(data.getBytes(StandardCharsets.UTF_8));
        
        byte[] signatureBytes = Base64.getDecoder().decode(signatureString);
        return signature.verify(signatureBytes);
    }
}
```

---

## Session Management Patterns

### 1. Secure Session Configuration

**Session Security Config:**
```java
@Configuration
public class SessionSecurityConfig {
    
    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }
    
    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .maximumSessions(3)
                .maxSessionsPreventsLogin(false)
                .sessionRegistry(sessionRegistry())
                .expiredUrl("/login?expired")
                .and()
                .sessionFixation().migrateSession()
                .invalidSessionUrl("/login?invalid")
            )
            .rememberMe(remember -> remember
                .key("uniqueAndSecret")
                .tokenValiditySeconds(86400)
                .userDetailsService(userDetailsService())
            );
        
        return http.build();
    }
}
```

### 2. Custom Session Management

**Session Service:**
```java
@Service
public class SessionService {
    
    @Autowired
    private SessionRegistry sessionRegistry;
    
    @Autowired
    private RedisTemplate<String, Object> redisTemplate;
    
    public void invalidateUserSessions(String username) {
        List<SessionInformation> sessions = sessionRegistry.getAllSessions(username, false);
        sessions.forEach(SessionInformation::expireNow);
    }
    
    public void trackUserActivity(String username, String activity) {
        String key = "user:activity:" + username;
        UserActivity userActivity = UserActivity.builder()
            .username(username)
            .activity(activity)
            .timestamp(Instant.now())
            .ipAddress(getCurrentUserIp())
            .build();
        
        redisTemplate.opsForList().rightPush(key, userActivity);
        redisTemplate.expire(key, Duration.ofDays(30));
    }
    
    public List<UserActivity> getUserActivities(String username) {
        String key = "user:activity:" + username;
        List<Object> activities = redisTemplate.opsForList().range(key, 0, -1);
        return activities.stream()
            .map(obj -> (UserActivity) obj)
            .collect(Collectors.toList());
    }
    
    private String getCurrentUserIp() {
        RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
        if (attributes instanceof ServletRequestAttributes) {
            HttpServletRequest request = ((ServletRequestAttributes) attributes).getRequest();
            return request.getRemoteAddr();
        }
        return "unknown";
    }
}
```

---

## CSRF Protection

### 1. CSRF Configuration

**CSRF Security Config:**
```java
@Configuration
public class CsrfSecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .ignoringRequestMatchers("/api/public/**", "/webhooks/**")
                .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
            )
            .addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class);
        
        return http.build();
    }
}
```

**Custom CSRF Filter:**
```java
public class CsrfCookieFilter extends OncePerRequestFilter {
    
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                  HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        CsrfToken csrfToken = (CsrfToken) request.getAttribute("_csrf");
        if (csrfToken != null) {
            // Trigger token generation
            csrfToken.getToken();
        }
        
        filterChain.doFilter(request, response);
    }
}
```

### 2. CSRF Token in REST API

**CSRF Controller:**
```java
@RestController
public class CsrfController {
    
    @GetMapping("/api/csrf")
    public CsrfToken getCsrfToken(HttpServletRequest request) {
        return (CsrfToken) request.getAttribute("_csrf");
    }
}
```

---

## Rate Limiting Pattern

### 1. Bucket4j Rate Limiting

**Rate Limiting Service:**
```java
@Service
public class RateLimitingService {
    
    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();
    
    public Bucket createBucket(String key, RateLimitType type) {
        return switch (type) {
            case API_CALLS -> Bucket.builder()
                .addLimit(Bandwidth.simple(100, Duration.ofMinutes(1)))
                .addLimit(Bandwidth.simple(1000, Duration.ofHours(1)))
                .build();
            case LOGIN_ATTEMPTS -> Bucket.builder()
                .addLimit(Bandwidth.simple(5, Duration.ofMinutes(15)))
                .build();
            case FILE_UPLOADS -> Bucket.builder()
                .addLimit(Bandwidth.simple(10, Duration.ofMinutes(1)))
                .build();
        };
    }
    
    public boolean tryConsume(String key, RateLimitType type) {
        Bucket bucket = buckets.computeIfAbsent(key, k -> createBucket(k, type));
        return bucket.tryConsume(1);
    }
    
    public long getAvailableTokens(String key, RateLimitType type) {
        Bucket bucket = buckets.computeIfAbsent(key, k -> createBucket(k, type));
        return bucket.getAvailableTokens();
    }
}
```

**Rate Limiting Aspect:**
```java
@Aspect
@Component
public class RateLimitingAspect {
    
    @Autowired
    private RateLimitingService rateLimitingService;
    
    @Around("@annotation(rateLimit)")
    public Object rateLimit(ProceedingJoinPoint joinPoint, RateLimit rateLimit) throws Throwable {
        String key = generateKey(joinPoint, rateLimit);
        
        if (!rateLimitingService.tryConsume(key, rateLimit.type())) {
            throw new RateLimitExceededException("Rate limit exceeded for " + rateLimit.type());
        }
        
        return joinPoint.proceed();
    }
    
    private String generateKey(ProceedingJoinPoint joinPoint, RateLimit rateLimit) {
        // Generate key based on IP, user, or other criteria
        String userIdentifier = getCurrentUserIdentifier();
        return rateLimit.type() + ":" + userIdentifier;
    }
}
```

**Rate Limit Annotation:**
```java
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface RateLimit {
    RateLimitType type();
}

public enum RateLimitType {
    API_CALLS,
    LOGIN_ATTEMPTS,
    FILE_UPLOADS
}
```

---

## SQL Injection Prevention

### 1. Prepared Statements

**Repository with Prepared Statements:**
```java
@Repository
public class UserRepository {
    
    @Autowired
    private JdbcTemplate jdbcTemplate;
    
    public User findUserByEmail(String email) {
        String sql = "SELECT * FROM users WHERE email = ?";
        return jdbcTemplate.queryForObject(sql, new Object[]{email}, new UserRowMapper());
    }
    
    public List<User> findUsersByRole(String role) {
        String sql = "SELECT u.* FROM users u JOIN user_roles ur ON u.id = ur.user_id " +
                    "JOIN roles r ON ur.role_id = r.id WHERE r.name = ?";
        return jdbcTemplate.query(sql, new Object[]{role}, new UserRowMapper());
    }
    
    public int updateUserLastLogin(Long userId, Timestamp lastLogin) {
        String sql = "UPDATE users SET last_login = ? WHERE id = ?";
        return jdbcTemplate.update(sql, lastLogin, userId);
    }
}
```

### 2. JPA Query Security

**Secure JPA Queries:**
```java
@Repository
public interface UserJpaRepository extends JpaRepository<User, Long> {
    
    @Query("SELECT u FROM User u WHERE u.email = :email")
    Optional<User> findByEmail(@Param("email") String email);
    
    @Query("SELECT u FROM User u WHERE u.username LIKE %:username% AND u.active = true")
    List<User> findActiveUsersByUsername(@Param("username") String username);
    
    @Query(value = "SELECT * FROM users WHERE created_date BETWEEN :startDate AND :endDate", 
           nativeQuery = true)
    List<User> findUsersByDateRange(@Param("startDate") LocalDate startDate, 
                                   @Param("endDate") LocalDate endDate);
    
    @Modifying
    @Query("UPDATE User u SET u.active = false WHERE u.lastLogin < :cutoffDate")
    int deactivateInactiveUsers(@Param("cutoffDate") LocalDateTime cutoffDate);
}
```

---

## Audit Logging Pattern

### 1. Security Event Logging

**Audit Service:**
```java
@Service
public class AuditService {
    
    private static final Logger auditLogger = LoggerFactory.getLogger("AUDIT");
    
    @Autowired
    private AuditRepository auditRepository;
    
    @Async
    public void logSecurityEvent(SecurityEventType eventType, String username, 
                               String details, String ipAddress) {
        AuditEvent auditEvent = AuditEvent.builder()
            .eventType(eventType)
            .username(username)
            .details(details)
            .ipAddress(ipAddress)
            .timestamp(Instant.now())
            .sessionId(getCurrentSessionId())
            .userAgent(getCurrentUserAgent())
            .build();
        
        // Log to file
        auditLogger.info("Security Event: {}", auditEvent);
        
        // Save to database
        auditRepository.save(auditEvent);
        
        // Send to SIEM if critical
        if (eventType.isCritical()) {
            sendToSiem(auditEvent);
        }
    }
    
    @EventListener
    public void handleAuthenticationSuccess(AuthenticationSuccessEvent event) {
        String username = event.getAuthentication().getName();
        logSecurityEvent(SecurityEventType.LOGIN_SUCCESS, username, 
                        "User logged in successfully", getCurrentUserIp());
    }
    
    @EventListener
    public void handleAuthenticationFailure(AbstractAuthenticationFailureEvent event) {
        String username = event.getAuthentication().getName();
        String reason = event.getException().getMessage();
        logSecurityEvent(SecurityEventType.LOGIN_FAILURE, username, 
                        "Login failed: " + reason, getCurrentUserIp());
    }
    
    @EventListener
    public void handleAuthorizationFailure(AuthorizationDeniedEvent event) {
        String username = event.getAuthentication().getName();
        logSecurityEvent(SecurityEventType.ACCESS_DENIED, username, 
                        "Access denied to resource", getCurrentUserIp());
    }
    
    private void sendToSiem(AuditEvent event) {
        // Implementation to send critical events to SIEM system
        // This could be via REST API, message queue, or log aggregation
    }
    
    private String getCurrentSessionId() {
        RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
        if (attributes instanceof ServletRequestAttributes) {
            HttpServletRequest request = ((ServletRequestAttributes) attributes).getRequest();
            return request.getSession().getId();
        }
        return "unknown";
    }
    
    private String getCurrentUserAgent() {
        RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
        if (attributes instanceof ServletRequestAttributes) {
            HttpServletRequest request = ((ServletRequestAttributes) attributes).getRequest();
            return request.getHeader("User-Agent");
        }
        return "unknown";
    }
    
    private String getCurrentUserIp() {
        RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
        if (attributes instanceof ServletRequestAttributes) {
            HttpServletRequest request = ((ServletRequestAttributes) attributes).getRequest();
            String xForwardedFor = request.getHeader("X-Forwarded-For");
            if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
                return xForwardedFor.split(",")[0].trim();
            }
            return request.getRemoteAddr();
        }
        return "unknown";
    }
}
```

**Audit Event Entity:**
```java
@Entity
@Table(name = "audit_events")
public class AuditEvent {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Enumerated(EnumType.STRING)
    @Column(name = "event_type", nullable = false)
    private SecurityEventType eventType;
    
    @Column(name = "username")
    private String username;
    
    @Column(name = "details", length = 1000)
    private String details;
    
    @Column(name = "ip_address")
    private String ipAddress;
    
    @Column(name = "session_id")
    private String sessionId;
    
    @Column(name = "user_agent", length = 500)
    private String userAgent;
    
    @Column(name = "timestamp", nullable = false)
    private Instant timestamp;
    
    @Column(name = "severity")
    @Enumerated(EnumType.STRING)
    private SecuritySeverity severity;
    
    // Constructors, getters, setters, and builder
}

public enum SecurityEventType {
    LOGIN_SUCCESS(false, SecuritySeverity.INFO),
    LOGIN_FAILURE(false, SecuritySeverity.WARNING),
    LOGOUT(false, SecuritySeverity.INFO),
    ACCESS_DENIED(true, SecuritySeverity.WARNING),
    PASSWORD_CHANGE(false, SecuritySeverity.INFO),
    ACCOUNT_LOCKED(true, SecuritySeverity.HIGH),
    PRIVILEGE_ESCALATION(true, SecuritySeverity.CRITICAL),
    DATA_BREACH_ATTEMPT(true, SecuritySeverity.CRITICAL),
    SUSPICIOUS_ACTIVITY(true, SecuritySeverity.HIGH);
    
    private final boolean critical;
    private final SecuritySeverity severity;
    
    SecurityEventType(boolean critical, SecuritySeverity severity) {
        this.critical = critical;
        this.severity = severity;
    }
    
    public boolean isCritical() {
        return critical;
    }
    
    public SecuritySeverity getSeverity() {
        return severity;
    }
}

public enum SecuritySeverity {
    INFO, WARNING, HIGH, CRITICAL
}
```

### 2. Audit Aspect for Method Calls

**Audit Aspect:**
```java
@Aspect
@Component
public class AuditAspect {
    
    @Autowired
    private AuditService auditService;
    
    @Around("@annotation(auditable)")
    public Object auditMethod(ProceedingJoinPoint joinPoint, Auditable auditable) throws Throwable {
        String methodName = joinPoint.getSignature().getName();
        String className = joinPoint.getTarget().getClass().getSimpleName();
        String username = getCurrentUsername();
        
        // Log method entry
        auditService.logSecurityEvent(
            auditable.eventType(),
            username,
            String.format("Method %s.%s called", className, methodName),
            getCurrentUserIp()
        );
        
        try {
            Object result = joinPoint.proceed();
            
            // Log successful completion
            auditService.logSecurityEvent(
                auditable.eventType(),
                username,
                String.format("Method %s.%s completed successfully", className, methodName),
                getCurrentUserIp()
            );
            
            return result;
        } catch (Exception e) {
            // Log method failure
            auditService.logSecurityEvent(
                SecurityEventType.SUSPICIOUS_ACTIVITY,
                username,
                String.format("Method %s.%s failed: %s", className, methodName, e.getMessage()),
                getCurrentUserIp()
            );
            throw e;
        }
    }
    
    private String getCurrentUsername() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return authentication != null ? authentication.getName() : "anonymous";
    }
}
```

**Auditable Annotation:**
```java
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface Auditable {
    SecurityEventType eventType() default SecurityEventType.SUSPICIOUS_ACTIVITY;
    String description() default "";
}
```

---

## Secure Configuration Pattern

### 1. Environment-based Security

**Production Security Config:**
```java
@Configuration
@Profile("production")
public class ProductionSecurityConfig {
    
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // Force HTTPS
            .requiresChannel(channel -> channel.anyRequest().requiresSecure())
            
            // Security headers
            .headers(headers -> headers
                .frameOptions().deny()
                .contentTypeOptions().and()
                .httpStrictTransportSecurity(hsts -> hsts
                    .maxAgeInSeconds(31536000) // 1 year
                    .includeSubdomains(true)
                    .preload(true)
                )
                .and()
                .addHeaderWriter(new StaticHeadersWriter("X-Content-Type-Options", "nosniff"))
                .addHeaderWriter(new StaticHeadersWriter("X-XSS-Protection", "1; mode=block"))
                .addHeaderWriter(new StaticHeadersWriter("Referrer-Policy", "strict-origin-when-cross-origin"))
                .addHeaderWriter(new StaticHeadersWriter("Feature-Policy", 
                    "geolocation 'none'; microphone 'none'; camera 'none'"))
            )
            
            // Session management
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .maximumSessions(1)
                .maxSessionsPreventsLogin(true)
            )
            
            // CORS configuration
            .cors(cors -> cors.configurationSource(corsConfigurationSource()));
        
        return http.build();
    }
    
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOriginPatterns(Arrays.asList("https://*.yourdomain.com"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", configuration);
        return source;
    }
}
```

### 2. Secure Properties Configuration

**Encrypted Properties:**
```java
@Configuration
@EnableConfigurationProperties
public class SecurePropertiesConfig {
    
    @Bean
    public static PropertySourcesPlaceholderConfigurer propertySourcesPlaceholderConfigurer() {
        PropertySourcesPlaceholderConfigurer configurer = new PropertySourcesPlaceholderConfigurer();
        configurer.setLocation(new ClassPathResource("application-encrypted.properties"));
        return configurer;
    }
    
    @Bean
    public TextEncryptor textEncryptor() {
        return Encryptors.text("password", "salt");
    }
}
```

**Secure Configuration Properties:**
```java
@ConfigurationProperties(prefix = "security")
@Component
public class SecurityProperties {
    
    private String jwtSecret;
    private Long jwtExpiration;
    private String encryptionKey;
    private Integer bcryptRounds;
    private String allowedOrigins;
    private Integer sessionTimeout;
    private Integer maxLoginAttempts;
    private Integer lockoutDuration;
    
    // Getters and setters with validation
    
    public void setJwtSecret(String jwtSecret) {
        if (jwtSecret == null || jwtSecret.length() < 32) {
            throw new IllegalArgumentException("JWT secret must be at least 32 characters");
        }
        this.jwtSecret = jwtSecret;
    }
    
    public void setBcryptRounds(Integer bcryptRounds) {
        if (bcryptRounds == null || bcryptRounds < 10 || bcryptRounds > 15) {
            throw new IllegalArgumentException("BCrypt rounds must be between 10 and 15");
        }
        this.bcryptRounds = bcryptRounds;
    }
}
```

### 3. Security Health Checks

**Security Health Indicator:**
```java
@Component
public class SecurityHealthIndicator implements HealthIndicator {
    
    @Autowired
    private SecurityProperties securityProperties;
    
    @Override
    public Health health() {
        try {
            // Check critical security configurations
            Map<String, Object> details = new HashMap<>();
            
            // Check JWT configuration
            boolean jwtConfigured = securityProperties.getJwtSecret() != null && 
                                  securityProperties.getJwtSecret().length() >= 32;
            details.put("jwt.configured", jwtConfigured);
            
            // Check encryption configuration
            boolean encryptionConfigured = securityProperties.getEncryptionKey() != null &&
                                         securityProperties.getEncryptionKey().length() >= 32;
            details.put("encryption.configured", encryptionConfigured);
            
            // Check HTTPS enforcement
            boolean httpsEnforced = isHttpsEnforced();
            details.put("https.enforced", httpsEnforced);
            
            // Check session configuration
            boolean sessionSecure = securityProperties.getSessionTimeout() != null &&
                                  securityProperties.getSessionTimeout() > 0;
            details.put("session.configured", sessionSecure);
            
            if (jwtConfigured && encryptionConfigured && httpsEnforced && sessionSecure) {
                return Health.up().withDetails(details).build();
            } else {
                return Health.down().withDetails(details).build();
            }
            
        } catch (Exception e) {
            return Health.down().withException(e).build();
        }
    }
    
    private boolean isHttpsEnforced() {
        // Check if HTTPS is properly configured
        return true; // Implementation depends on your setup
    }
}
```

---

## Best Practices

### 1. Secure Coding Guidelines

**Input Validation:**
- Always validate input on both client and server sides
- Use whitelist validation rather than blacklist
- Sanitize all user inputs before processing
- Implement proper error handling without exposing sensitive information

**Authentication & Authorization:**
- Use strong password policies and multi-factor authentication
- Implement proper session management
- Use the principle of least privilege
- Regularly review and update access controls

**Data Protection:**
- Encrypt sensitive data at rest and in transit
- Use secure communication protocols (HTTPS/TLS)
- Implement proper key management
- Regular security audits and penetration testing

### 2. Security Testing

**Unit Tests for Security:**
```java
@SpringBootTest
@AutoConfigureTestDatabase
class SecurityIntegrationTest {
    
    @Autowired
    private TestRestTemplate restTemplate;
    
    @Test
    void testUnauthorizedAccess() {
        ResponseEntity<String> response = restTemplate.getForEntity("/api/admin/users", String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }
    
    @Test
    void testSqlInjectionPrevention() {
        String maliciousInput = "'; DROP TABLE users; --";
        ResponseEntity<String> response = restTemplate.postForEntity("/api/users/search", 
            maliciousInput, String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }
    
    @Test
    void testXSSPrevention() {
        String xssPayload = "<script>alert('XSS')</script>";
        ResponseEntity<String> response = restTemplate.postForEntity("/api/comments", 
            xssPayload, String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }
    
    @Test
    void testRateLimiting() {
        // Make multiple requests to test rate limiting
        for (int i = 0; i < 101; i++) {
            ResponseEntity<String> response = restTemplate.getForEntity("/api/data", String.class);
            if (i < 100) {
                assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
            } else {
                assertThat(response.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
            }
        }
    }
}
```

### 3. Security Monitoring

**Security Metrics:**
```java
@Component
public class SecurityMetrics {
    
    private final MeterRegistry meterRegistry;
    private final Counter loginAttempts;
    private final Counter loginFailures;
    private final Counter accessDenied;
    
    public SecurityMetrics(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
        this.loginAttempts = Counter.builder("security.login.attempts")
            .description("Total login attempts")
            .register(meterRegistry);
        this.loginFailures = Counter.builder("security.login.failures")
            .description("Failed login attempts")
            .register(meterRegistry);
        this.accessDenied = Counter.builder("security.access.denied")
            .description("Access denied events")
            .register(meterRegistry);
    }
    
    public void recordLoginAttempt() {
        loginAttempts.increment();
    }
    
    public void recordLoginFailure() {
        loginFailures.increment();
    }
    
    public void recordAccessDenied() {
        accessDenied.increment();
    }
}
```

### 4. Security Checklist

**Pre-Production Security Checklist:**

- [ ] All endpoints properly secured with authentication/authorization
- [ ] Input validation implemented for all user inputs
- [ ] SQL injection prevention measures in place
- [ ] XSS protection implemented
- [ ] CSRF protection enabled
- [ ] Rate limiting configured
- [ ] Secure session management
- [ ] HTTPS enforced in production
- [ ] Security headers configured
- [ ] Sensitive data encrypted
- [ ] Proper error handling without information disclosure
- [ ] Audit logging implemented
- [ ] Security testing completed
- [ ] Dependency vulnerabilities checked
- [ ] Security configuration reviewed

**Regular Security Maintenance:**

- [ ] Regular security audits
- [ ] Dependency vulnerability scans
- [ ] Penetration testing
- [ ] Security log review
- [ ] Access control review
- [ ] Incident response plan testing
- [ ] Security awareness training
- [ ] Security policy updates

---

## Conclusion

This comprehensive guide covers the essential security patterns and implementations for Java applications. Remember that security is not a one-time implementation but an ongoing process that requires regular updates, monitoring, and improvement.

Key takeaways:
- Implement defense in depth with multiple security layers
- Follow the principle of least privilege
- Validate and sanitize all inputs
- Use secure coding practices consistently
- Regularly audit and test security measures
- Stay updated with latest security threats and patches
- Monitor and log security events
- Have an incident response plan ready

Security should be integrated into every phase of the development lifecycle, from design to deployment and maintenance.
