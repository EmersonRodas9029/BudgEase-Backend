package com.codepuppeteer.sistema_gastos_clientes.service.impl;

import com.codepuppeteer.sistema_gastos_clientes.dto.auth.LoginRequest;
import com.codepuppeteer.sistema_gastos_clientes.dto.auth.LoginResponse;
import com.codepuppeteer.sistema_gastos_clientes.entity.RefreshToken;
import com.codepuppeteer.sistema_gastos_clientes.entity.Usuario;
import com.codepuppeteer.sistema_gastos_clientes.exception.UnauthorizedException;
import com.codepuppeteer.sistema_gastos_clientes.repository.RefreshTokenRepository;
import com.codepuppeteer.sistema_gastos_clientes.repository.UsuarioRepository;
import com.codepuppeteer.sistema_gastos_clientes.service.interfaces.AuthService;
import com.codepuppeteer.sistema_gastos_clientes.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private static final Logger SECURITY_LOG = LoggerFactory.getLogger("SECURITY");

    private final AuthenticationManager authenticationManager;
    private final UsuarioRepository usuarioRepository;
    private final JwtUtil jwtUtil;
    private final RefreshTokenRepository refreshTokenRepository;

    @Value("${jwt.refresh-expiration}")
    private Long refreshExpiration;

    @Override
    @Transactional
    public LoginResponse login(LoginRequest request) {
        Usuario usuario = usuarioRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> {
                    SECURITY_LOG.warn("Login fallido: usuario inexistente '{}'", request.getUsername());
                    return new UnauthorizedException("Credenciales inválidas");
                });

        // Verificar si el usuario está bloqueado
        if (usuario.getBloqueadoHasta() != null && usuario.getBloqueadoHasta().isAfter(LocalDateTime.now())) {
            SECURITY_LOG.warn("Login rechazado: usuario '{}' bloqueado hasta {}", usuario.getUsername(), usuario.getBloqueadoHasta());
            throw new UnauthorizedException("Usuario bloqueado temporalmente. Intente más tarde.");
        }

        // Verificar si el usuario está activo
        if (!usuario.getActivo()) {
            SECURITY_LOG.warn("Login rechazado: usuario '{}' inactivo", usuario.getUsername());
            throw new UnauthorizedException("Usuario inactivo");
        }

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
            );

            // Resetear intentos fallidos en login exitoso
            if (usuario.getIntentosFallidos() > 0) {
                usuario.setIntentosFallidos(0);
                usuario.setBloqueadoHasta(null);
            }

            // Actualizar último acceso
            usuario.setUltimoAcceso(LocalDateTime.now());
            usuarioRepository.save(usuario);
            SECURITY_LOG.info("Login exitoso: usuario '{}' (id={}, rol={})", usuario.getUsername(), usuario.getId(), usuario.getRol());

            // Generar token JWT con información adicional
            Map<String, Object> claims = new HashMap<>();
            claims.put("userId", usuario.getId());
            claims.put("rol", usuario.getRol().name());
            claims.put("email", usuario.getEmail());

            String token = jwtUtil.generateToken(usuario.getUsername(), claims);
            String rawRefreshToken = createRefreshToken(usuario);

            return LoginResponse.builder()
                    .token(token)
                    .type("Bearer")
                    .userId(usuario.getId())
                    .username(usuario.getUsername())
                    .email(usuario.getEmail())
                    .rol(usuario.getRol().name())
                    .refreshToken(rawRefreshToken)
                    .build();

        } catch (BadCredentialsException e) {
            handleFailedLogin(usuario);
            throw new UnauthorizedException("Credenciales inválidas");
        } catch (DisabledException e) {
            SECURITY_LOG.warn("Login rechazado: usuario '{}' deshabilitado", usuario.getUsername());
            throw new UnauthorizedException("Usuario deshabilitado");
        }
    }

    @Override
    @Transactional
    public LoginResponse refresh(String refreshToken) {
        RefreshToken stored = refreshTokenRepository.findByToken(hash(refreshToken))
                .orElseThrow(() -> new UnauthorizedException("Refresh token inválido"));

        if (stored.getRevoked() || stored.getExpiryDate().isBefore(LocalDateTime.now())) {
            SECURITY_LOG.warn("Refresh rechazado: token revocado o expirado (usuario id={})", stored.getUsuario().getId());
            throw new UnauthorizedException("Refresh token inválido o expirado");
        }

        Usuario usuario = stored.getUsuario();
        stored.setRevoked(true);
        refreshTokenRepository.save(stored);

        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", usuario.getId());
        claims.put("rol", usuario.getRol().name());
        claims.put("email", usuario.getEmail());
        String newAccessToken = jwtUtil.generateToken(usuario.getUsername(), claims);
        String newRefreshToken = createRefreshToken(usuario);

        SECURITY_LOG.info("Token refrescado: usuario '{}' (id={})", usuario.getUsername(), usuario.getId());

        return LoginResponse.builder()
                .token(newAccessToken)
                .type("Bearer")
                .userId(usuario.getId())
                .username(usuario.getUsername())
                .email(usuario.getEmail())
                .rol(usuario.getRol().name())
                .refreshToken(newRefreshToken)
                .build();
    }

    @Override
    @Transactional
    public void logout(String refreshToken) {
        refreshTokenRepository.findByToken(hash(refreshToken)).ifPresent(stored -> {
            stored.setRevoked(true);
            refreshTokenRepository.save(stored);
        });
    }

    private String createRefreshToken(Usuario usuario) {
        String raw = generateSecureRandomToken();
        RefreshToken entity = RefreshToken.builder()
                .token(hash(raw))
                .usuario(usuario)
                .expiryDate(LocalDateTime.now().plusSeconds(refreshExpiration / 1000))
                .revoked(false)
                .build();
        refreshTokenRepository.save(entity);
        return raw;
    }

    private String generateSecureRandomToken() {
        byte[] bytes = new byte[64];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String hash(String raw) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(digest.digest(raw.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private void handleFailedLogin(Usuario usuario) {
        int intentos = usuario.getIntentosFallidos() + 1;
        usuario.setIntentosFallidos(intentos);

        // Bloquear usuario después de 5 intentos fallidos por 15 minutos
        if (intentos >= 5) {
            usuario.setBloqueadoHasta(LocalDateTime.now().plusMinutes(15));
            SECURITY_LOG.warn("Usuario '{}' bloqueado 15 minutos tras {} intentos fallidos", usuario.getUsername(), intentos);
        } else {
            SECURITY_LOG.warn("Login fallido: contraseña incorrecta para '{}' (intento {}/5)", usuario.getUsername(), intentos);
        }

        usuarioRepository.save(usuario);
    }
}
