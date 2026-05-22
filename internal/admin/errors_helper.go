package admin

import (
	"github.com/gin-gonic/gin"
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
