// Package ai provides retrieval‑augmented generation (RAG) utilities that
// combine a local embedding model with an in‑memory vector store to ground
// LLM answers in private data.
package ai

import (
	"context"
	"fmt"
	"math"
	"strings"
	"sync"

	"go.uber.org/zap"
)

// Document represents a piece of text with its embedding vector.
type Document struct {
	ID       string
	Content  string
	Embedding []float32
}

// Store holds documents and provides similarity search.
type Store struct {
	mu      sync.RWMutex
	docs    map[string]*Document
	embedFn func(ctx context.Context, text string) ([]float32, error)
	logger  *zap.Logger
}

// NewStore creates a store that uses the supplied embedding function.
func NewStore(emb func(ctx context.Context, text string) ([]float32, error), log *zap.Logger) *Store {
	if log == nil {
		log = zap.NewNop()
	}
	return &Store{
		docs:    make(map[string]*Document),
		embedFn: emb,
		logger:  log,
	}
}

// Add stores a document, computing its embedding via the store's embedFn.
func (s *Store) Add(ctx context.Context, id, text string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	emb, err := s.embedFn(ctx, text)
	if err != nil {
		return err
	}
	s.docs[id] = &Document{
		ID:       id,
		Content:  text,
		Embedding: emb,
	}
	s.logger.Debug("document added to RAG store", zap.String("id", id), zap.Int("dim", len(emb)))
	return nil
}

// cosineSimilarity computes cosine similarity between two vectors.
func cosineSimilarity(a, b []float32) float64 {
	if len(a) != len(b) {
		return 0
	}
	var dot, normA, normB float64
	for i := range a {
		dot += float64(a[i]) * float64(b[i])
		normA += float64(a[i]) * float64(a[i])
		nb := float64(b[i])
		normB += nb * nb
	}
	if normA == 0 || normB == 0 {
		return 0
	}
	return dot / (math.Sqrt(normA) * math.Sqrt(normB))
}

// Search returns the top k documents most similar to the query text.
func (s *Store) Search(ctx context.Context, query string, k int) ([]*Document, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.docs) == 0 {
		return nil, nil
	}
	qryEmb, err := s.embedFn(ctx, query)
	if err != nil {
		return nil, err
	}
	type item struct {
		doc  *Document
		score float64
	}
	var items []item
	for _, doc := range s.docs {
		items = append(items, item{doc: doc, score: cosineSimilarity(qryEmb, doc.Embedding)})
	}
	// selection sort for top k
	if k > len(items) {
		k = len(items)
	}
	for i := 0; i < k; i++ {
		maxIdx := i
		for j := i + 1; j < len(items); j++ {
			if items[j].score > items[maxIdx].score {
				maxIdx = j
			}
		}
		if maxIdx != i {
			items[i], items[maxIdx] = items[maxIdx], items[i]
		}
	}
	result := make([]*Document, k)
	for i := 0; i < k; i++ {
		result[i] = items[i].doc
	}
	return result, nil
}

// RAGContext builds a prompt that combines retrieved documents with a user query.
func RAGContext(query string, docs []*Document) string {
	if len(docs) == 0 {
		return query
	}
	var sb strings.Builder
	sb.WriteString("Answer the question using only the following context:\n\n")
	for i, d := range docs {
		fmt.Fprintf(&sb, "[Source %d]:\n%s\n\n", i+1, d.Content)
	}
	sb.WriteString("Question: ")
	sb.WriteString(query)
	return sb.String()
}
