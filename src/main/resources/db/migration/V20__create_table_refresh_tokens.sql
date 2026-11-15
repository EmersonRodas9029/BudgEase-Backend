CREATE TABLE refresh_tokens (
                                 id BIGINT AUTO_INCREMENT PRIMARY KEY,
                                 token VARCHAR(255) NOT NULL UNIQUE,
                                 usuario_id BIGINT NOT NULL,
                                 expiry_date TIMESTAMP NOT NULL,
                                 revoked BOOLEAN NOT NULL DEFAULT FALSE,
                                 fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                 CONSTRAINT fk_refresh_tokens_usuario FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE,
                                 INDEX idx_refresh_tokens_usuario (usuario_id)
);
