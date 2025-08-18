package types

// PackageInfo represents metadata about a package from a repository
type PackageInfo struct {
	Name        string                 `json:"name"`
	Version     string                 `json:"version"`
	Description string                 `json:"description,omitempty"`
	Type        string                 `json:"type,omitempty"`
	Keywords    []string               `json:"keywords,omitempty"`
	Homepage    string                 `json:"homepage,omitempty"`
	License     []string               `json:"license,omitempty"`
	Authors     []PackageAuthor        `json:"authors,omitempty"`
	Require     map[string]string      `json:"require,omitempty"`
	RequireDev  map[string]string      `json:"require-dev,omitempty"`
	Extra       map[string]any `json:"extra,omitempty"`
	Repository  string                 `json:"repository,omitempty"` // Source repository
	IsPrivate   bool                   `json:"is_private,omitempty"`
}

// PackageAuthor represents package author information
type PackageAuthor struct {
	Name     string `json:"name"`
	Email    string `json:"email,omitempty"`
	Homepage string `json:"homepage,omitempty"`
	Role     string `json:"role,omitempty"`
}