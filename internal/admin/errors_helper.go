package admin

import (
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	apperrors "github.com/openidx/openidx/internal/common/errors"
)

// respondError sends a structured error response using the common errors package.
func respondError(c *gin.Context, logger *zap.Logger, err *apperrors.AppError) {
	if logger != nil && err.Err != nil {
		logger.Error(err.Message, zap.Error(err.Err), zap.String("code", string(err.Code)))
	}
	apperrors.HandleError(c, err)
}

// handleDBError checks a database error and sends the appropriate response.
// Returns true if an error was handled (caller should return), false if no error.
func handleDBError(c *gin.Context, logger *zap.Logger, err error, resource string) bool {
	if err == nil {
		return false
	}
	if err == pgx.ErrNoRows {
		respondError(c, nil, apperrors.NotFound(resource))
		return true
	}
	respondError(c, logger, apperrors.Internal("database error", err).WithDetails(resource))
	return true
}
