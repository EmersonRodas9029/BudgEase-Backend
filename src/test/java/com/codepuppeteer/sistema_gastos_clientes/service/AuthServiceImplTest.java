package com.codepuppeteer.sistema_gastos_clientes.service;

import com.codepuppeteer.sistema_gastos_clientes.dto.auth.LoginResponse;
import com.codepuppeteer.sistema_gastos_clientes.entity.RefreshToken;
import com.codepuppeteer.sistema_gastos_clientes.entity.Usuario;
import com.codepuppeteer.sistema_gastos_clientes.enums.Rol;
import com.codepuppeteer.sistema_gastos_clientes.exception.UnauthorizedException;
import com.codepuppeteer.sistema_gastos_clientes.repository.RefreshTokenRepository;
import com.codepuppeteer.sistema_gastos_clientes.repository.UsuarioRepository;
import com.codepuppeteer.sistema_gastos_clientes.service.impl.AuthServiceImpl;
import com.codepuppeteer.sistema_gastos_clientes.util.JwtUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

// Cubre la rotación de refresh tokens agregada para que la sesión del frontend pueda
// renovarse sola en vez de depender de que el JWT de acceso dure 24h sin control alguno.
@ExtendWith(MockitoExtension.class)
class AuthServiceImplTest {

    @Mock private AuthenticationManager authenticationManager;
    @Mock private UsuarioRepository usuarioRepository;
    @Mock private JwtUtil jwtUtil;
    @Mock private RefreshTokenRepository refreshTokenRepository;

    private AuthServiceImpl service;
    private Usuario usuario;

    @BeforeEach
    void setUp() {
        service = new AuthServiceImpl(authenticationManager, usuarioRepository, jwtUtil, refreshTokenRepository);
        ReflectionTestUtils.setField(service, "refreshExpiration", 1_209_600_000L);

        usuario = Usuario.builder()
                .id(1L).username("ana").email("ana@test.com").rol(Rol.CLIENTE)
                .activo(true).intentosFallidos(0)
                .build();

        lenient().when(jwtUtil.generateToken(anyString(), any())).thenReturn("mocked-jwt");
    }

    @Test
    void refresh_conTokenValido_revocaElViejoYDevuelveTokensNuevos() {
        RefreshToken stored = RefreshToken.builder()
                .id(10L).token("hash-no-importa").usuario(usuario)
                .expiryDate(LocalDateTime.now().plusDays(1)).revoked(false)
                .build();
        when(refreshTokenRepository.findByToken(anyString())).thenReturn(Optional.of(stored));

        LoginResponse response = service.refresh("raw-refresh-token-cualquiera");

        assertEquals("mocked-jwt", response.getToken());
        assertNotNull(response.getRefreshToken());
        assertEquals("ana", response.getUsername());
        assertTrue(stored.getRevoked(), "el refresh token usado debe quedar revocado (rotación)");
        verify(refreshTokenRepository, times(2)).save(any());
    }

    @Test
    void refresh_conTokenRevocado_lanzaUnauthorized() {
        RefreshToken stored = RefreshToken.builder()
                .token("x").usuario(usuario)
                .expiryDate(LocalDateTime.now().plusDays(1)).revoked(true)
                .build();
        when(refreshTokenRepository.findByToken(anyString())).thenReturn(Optional.of(stored));

        assertThrows(UnauthorizedException.class, () -> service.refresh("raw"));
    }

    @Test
    void refresh_conTokenExpirado_lanzaUnauthorized() {
        RefreshToken stored = RefreshToken.builder()
                .token("x").usuario(usuario)
                .expiryDate(LocalDateTime.now().minusMinutes(1)).revoked(false)
                .build();
        when(refreshTokenRepository.findByToken(anyString())).thenReturn(Optional.of(stored));

        assertThrows(UnauthorizedException.class, () -> service.refresh("raw"));
    }

    @Test
    void refresh_conTokenInexistente_lanzaUnauthorized() {
        when(refreshTokenRepository.findByToken(anyString())).thenReturn(Optional.empty());

        assertThrows(UnauthorizedException.class, () -> service.refresh("raw"));
    }

    @Test
    void logout_marcaElRefreshTokenComoRevocado() {
        RefreshToken stored = RefreshToken.builder()
                .token("x").usuario(usuario)
                .expiryDate(LocalDateTime.now().plusDays(1)).revoked(false)
                .build();
        when(refreshTokenRepository.findByToken(anyString())).thenReturn(Optional.of(stored));

        service.logout("raw");

        assertTrue(stored.getRevoked());
        verify(refreshTokenRepository).save(stored);
    }

    @Test
    void logout_conTokenQueNoExiste_noLanzaError() {
        when(refreshTokenRepository.findByToken(anyString())).thenReturn(Optional.empty());

        assertDoesNotThrow(() -> service.logout("raw"));
        verify(refreshTokenRepository, never()).save(any());
    }
}
