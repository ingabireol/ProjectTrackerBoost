package com.buildmaster.projecttracker.security.oauth2;

import java.util.Map;

// Google OAuth2 User Info implementation
class GoogleOAuth2UserInfo implements OAuth2UserInfo {
    private final Map<String, Object> attributes;

    public GoogleOAuth2UserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    @Override
    public String getId() {
        return (String) attributes.get("sub");
    }

    @Override
    public String getName() {
        String name = (String) attributes.get("name");
        if (name != null && !name.trim().isEmpty()) {
            return name;
        }

        // Fallback to given_name + family_name
        String givenName = (String) attributes.get("given_name");
        String familyName = (String) attributes.get("family_name");

        if (givenName != null && familyName != null) {
            return givenName + " " + familyName;
        } else if (givenName != null) {
            return givenName;
        } else if (familyName != null) {
            return familyName;
        }

        // Ultimate fallback to email prefix
        String email = getEmail();
        return email != null ? email.split("@")[0] : "Unknown User";
    }

    @Override
    public String getEmail() {
        return (String) attributes.get("email");
    }

    @Override
    public String getImageUrl() {
        return (String) attributes.get("picture");
    }
}
