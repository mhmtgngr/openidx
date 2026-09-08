package risk

import "math"

// haversineDistance returns the great-circle distance in kilometres.
//
// It lived in behavior.go, alongside a BehaviorTracker no binary ever
// constructed -- a second implementation of the behavioural baselines
// internal/admin/continuous_auth.go computes. Deleting that file took this with
// it, and this is the live half: the impossible-travel detector in anomaly.go,
// the geo-distance signal in scorer.go and service.go all measure with it.
func haversineDistance(lat1, lon1, lat2, lon2 float64) float64 {
	const earthRadius = 6371 // km

	lat1Rad := lat1 * math.Pi / 180
	lat2Rad := lat2 * math.Pi / 180
	dLat := (lat2 - lat1) * math.Pi / 180
	dLon := (lon2 - lon1) * math.Pi / 180

	a := math.Sin(dLat/2)*math.Sin(dLat/2) +
		math.Cos(lat1Rad)*math.Cos(lat2Rad)*math.Sin(dLon/2)*math.Sin(dLon/2)
	c := 2 * math.Atan2(math.Sqrt(a), math.Sqrt(1-a))

	return earthRadius * c
}
