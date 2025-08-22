# Keycloak Authentication Implementation Documentation

This document provides a comprehensive guide to the Keycloak authentication setup in a React application. It covers the key components, their roles, and the authentication flow, designed to be easy to understand for developers at all levels.

## Table of Contents

1. [Overview](#overview)
2. [Key Components](#key-components)
   - [main.jsx](#mainjsx)
   - [keycloak.jsx](#keycloakjsx)
   - [ClientIdForm.jsx](#clientidformjsx)
   - [AuthCallback.jsx](#authcallbackjsx)
   - [RequireAuth.jsx](#requireauthjsx)
   - [ProtectedRoute.jsx](#protectedroutejsx)
3. [Authentication Flow](#authentication-flow)
4. [Setup and Configuration](#setup-and-configuration)
5. [Usage](#usage)
6. [Error Handling](#error-handling)
7. [Dependencies](#dependencies)
8. [Security Considerations](#security-considerations)
9. [Troubleshooting](#troubleshooting)

## Overview

The application integrates Keycloak, an open-source identity and access management solution, to handle user authentication. The implementation uses a dynamic client ID and realm name fetched based on user input (email or username) and supports a seamless login process with token management, session handling, and route protection. The authentication flow includes a client ID form, Keycloak initialization, token refresh, and a callback to handle post-authentication data storage.

## Key Components

### main.jsx

This is the entry point of the React application, where the root component is rendered with necessary providers for authentication.

**Purpose**: Sets up the React application with `AuthProvider` and `KeycloakProvider` to provide authentication context to all components.

**Key Features**:

- Wraps the `App` component with `AuthProvider` and `KeycloakProvider`.
- Uses `createRoot` from `react-dom/client` for rendering.
- `StrictMode` is commented out, likely for development purposes to avoid double rendering.

**Code**:

```jsx
import { createRoot } from "react-dom/client";
import "./index.css";
import App from "./App.jsx";
import { StrictMode } from "react";
import AuthProvider from "./utils/context/AuthContext.jsx";
import { KeycloakProvider } from "./auth/keycloak";

createRoot(document.getElementById("root")).render(
  // <StrictMode>
  <AuthProvider>
    <KeycloakProvider>
      <App />
    </KeycloakProvider>
  </AuthProvider>
  // </StrictMode>
);
```

### keycloak.jsx

This file defines the `KeycloakProvider` and a custom hook `useKeycloak` to manage Keycloak authentication.

**Purpose**: Initializes the Keycloak instance, handles login/logout, and provides Keycloak context to child components.

**Key Features**:

- Creates a `KeycloakContext` to share Keycloak instance and methods.
- Initializes Keycloak with dynamic `keycloakName` (realm), `clientId`, and `loginHint`.
- Configures Keycloak with a specific URL and redirect URI.
- Provides a `logout` function that clears storage and redirects to the home page.
- Uses `keycloak-js` library for Keycloak integration.

**Code**:

```jsx
import { createContext, useContext, useState } from "react";
import Keycloak from "keycloak-js";

const KeycloakContext = createContext();

export const KeycloakProvider = ({ children }) => {
  const [keycloak, setKeycloakInstance] = useState(null);

  const initKeycloak = async (keycloakName, clientId, loginHint) => {
    const kc = new Keycloak({
      url: "your_server_url",
      realm: keycloakName,
      clientId,
    });

    const authenticated = await kc.init({
      onLoad: "login-required",
      loginHint,
      checkLoginIframe: false,
      redirectUri: window.location.origin + "/auth/callback",
    });

    if (authenticated) {
      setKeycloakInstance(kc);
      return kc;
    }

    return null;
  };

  const logout = () => {
    if (keycloak) {
      keycloak.logout({ redirectUri: window.location.origin });
      sessionStorage.clear();
      localStorage.clear();
      showToast("success", "Logged out successfully!");
    }
  };

  return (
    <KeycloakContext.Provider
      value={{ keycloak, initKeycloak, setKeycloakInstance, logout }}
    >
      {children}
    </KeycloakContext.Provider>
  );
};

export const useKeycloak = () => useContext(KeycloakContext);
```

### ClientIdForm.jsx

This component renders a form to collect user input (email or username) and fetches a dynamic client ID and realm name for Keycloak initialization.

**Purpose**: Allows users to input their email or username to retrieve a client ID and realm name, then initiate Keycloak authentication.

**Key Features**:

- Validates input for email or username (minimum 4 characters).
- Submits input to a backend API (`/users/get-keycloak-client-id`) to fetch the client ID and realm name.
- Stores `email`, `keycloakName`, and `clientId` in `sessionStorage`.
- Displays a loading state and error messages using a `showToast` utility.
- Uses custom UI components (`TextBox`, `Button`, `Loader`).

**Code**:

```jsx
import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useKeycloak } from "../../auth/keycloak";
import apiMethods from "../../utils/apiMethods";
import showToast from "../../utils/showToast";
import TextBox from "../../components/UI/Components/TextBox";
import Button from "../../components/UI/Buttons/Buttons";
import Loader from "../../components/UI/Components/Loader";

const ClientIdForm = () => {
  const [identifier, setIdentifier] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const navigate = useNavigate();
  const { initKeycloak } = useKeycloak();

  const validateInput = (value) => {
    if (!value.trim()) {
      return "Identifier is required";
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value) && value.length < 4) {
      return "Enter a valid email or username (min 4 characters)";
    }
    return "";
  };

  const handleBlur = () => {
    const validationError = validateInput(identifier);
    setError(validationError);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    const validationError = validateInput(identifier);
    setError(validationError);
    if (validationError) return;

    setLoading(true);
    try {
      const response = await apiMethods.postData(
        "/users/get-keycloak-client-id",
        {
          identifier,
        }
      );

      const { realm_name: keycloakName, keycloak_client_id } = response.data;

      if (!keycloak_client_id) {
        showToast("error", "Client ID not found");
        return;
      }

      console.log(
        "keycloakName:",
        keycloakName,
        "keycloak_client_id:",
        keycloak_client_id
      );

      sessionStorage.setItem("email", identifier);
      sessionStorage.setItem("keycloakName", keycloakName);
      sessionStorage.setItem("clientId", keycloak_client_id);

      await initKeycloak(keycloakName, keycloak_client_id, identifier);
    } catch (err) {
      console.error(err);
      showToast("error", err?.message || "Error logging in");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="login-form">
      <h3 className="text-center mb-4 heading-text">Login - Client</h3>
      <form onSubmit={handleSubmit}>
        <TextBox
          label="Email or Username"
          type="text"
          placeholder="Enter email or username"
          value={identifier}
          onChange={(e) => {
            setIdentifier(e.target.value);
            if (error) setError("");
          }}
          onBlur={handleBlur}
          error={error}
          autoFocus={true}
        />
        <Button
          label="Login"
          variant="primary"
          className="px-3 py-3 w-100 mb-3"
          loaderContent={<Loader className="fs-5 me-2" />}
          loader={loading}
          onClick={handleSubmit}
        />
      </form>
    </div>
  );
};

export default ClientIdForm;
```

### AuthCallback.jsx

This component handles the Keycloak callback after successful authentication, storing user data in MongoDB and updating the application state.

**Purpose**: Processes the Keycloak authentication response, stores tokens and user data, and redirects to the dashboard or requested path.

**Key Features**:

- Uses a `useRef` to prevent multiple executions of the callback logic.
- Retrieves `email`, `keycloakName`, and `clientId` from `sessionStorage`.
- Initializes Keycloak if not already done.
- Stores tokens in `localStorage`.
- Calls a backend API (`/auth/login`) to fetch user data and store it in MongoDB.
- Updates the `AuthContext` with user data and redirects to the appropriate page.

**Code**:

```jsx
import React, { useEffect, useState, useRef, useContext } from "react";
import { useNavigate } from "react-router-dom";
import { useKeycloak } from "../../auth/keycloak";
import apiMethods from "../../utils/apiMethods";
import showToast from "../../utils/showToast";
import Loader from "../../components/UI/Components/Loader";
import { AuthContext } from "../../utils/context/AuthContext";

const AuthCallback = () => {
  const navigate = useNavigate();
  const [error, setError] = useState("");
  const hasRun = useRef(false);
  const { login } = useContext(AuthContext);
  const { keycloak, initKeycloak, setKeycloakInstance } = useKeycloak();

  useEffect(() => {
    if (hasRun.current) return;
    hasRun.current = true;

    const email = sessionStorage.getItem("email");
    const keycloakName = sessionStorage.getItem("keycloakName");
    const clientId = sessionStorage.getItem("clientId");

    if (!email || !clientId) {
      showToast("error", "Session expired, please login again.");
      navigate("/");
      return;
    }

    const handleCallback = async () => {
      try {
        let activeKeycloak = keycloak;

        if (!activeKeycloak) {
          activeKeycloak = await initKeycloak(keycloakName, clientId, email);
          setKeycloakInstance(activeKeycloak);
        }

        if (!activeKeycloak?.token) {
          return;
        }

        localStorage.setItem("accessToken", activeKeycloak.token);
        localStorage.setItem("refreshToken", activeKeycloak.refreshToken);

        const response = await apiMethods.postData("/auth/login");

        const userData = {
          userId: response.data.userId,
          userName: response.data.username,
          userEmail: response.data.email,
          roleId: response.data.role,
          role: response.data.roleName,
          permissions: response.data.permissions || [],
          loggedInUserPermissions: response.data.permissions || [],
          userModulePermissions: response.data.userModulePermissions || [],
          isMFAEnabled: response.data.isMFAEnabled,
          isLoggedIn: response.data.isLoggedIn,
          qrCodeURL: response.data.qrCodeURL,
          authSecret: response.data.AuthSecret,
          createdAt: response.data.createdAt,
          isVerified: response.data.isVerified,
          modules: response.data.modules || [],
          clientId: response.data.client_id,
          keycloakClientId: response.data.keycloakClientId,
          accessToken: activeKeycloak.token,
          refreshToken: activeKeycloak.refreshToken,
          keycloakUserId: response.data.keycloakUserId,
        };

        localStorage.setItem("userData", JSON.stringify(userData));
        localStorage.setItem("isLoggedIn", "true");

        login(userData);

        sessionStorage.getItem("requestedPath")
          ? navigate(sessionStorage.getItem("requestedPath"))
          : navigate("/dashboard");
      } catch (err) {
        console.error("Callback error:", err);
        setError("Failed to complete login process");
        showToast("error", "Login failed");
      }
    };

    handleCallback();
  }, [navigate, login, keycloak, initKeycloak, setKeycloakInstance]);

  return (
    <div className="text-center mt-5 d-flex gap-3 align-items-center">
      <Loader className="fs-1 text-light" />
      <h4 className="text-center text-light">{error && error}</h4>
    </div>
  );
};

export default AuthCallback;
```

### RequireAuth.jsx

This component ensures that routes are protected by verifying user authentication and Keycloak token validity.

**Purpose**: Verifies the user's authentication state, refreshes tokens if necessary, and redirects unauthenticated users to the login page.

**Key Features**:

- Checks for `accessToken`, `refreshToken`, and `userData` in `localStorage`.
- Stores the requested path in `sessionStorage` for redirection after login.
- Reinitializes Keycloak if not already done, using stored `keycloakName`, `clientId`, and `email`.
- Refreshes tokens using Keycloak’s `updateToken` method if needed.
- Displays alerts for session expiration using `sweetalert2`.
- Renders child routes via `Outlet` if authenticated.

**Code**:

```jsx
import React, { useEffect, useState, useContext } from "react";
import { useNavigate, useLocation, Outlet } from "react-router-dom";
import Swal from "sweetalert2";
import { useKeycloak } from "../auth/keycloak";
import { AuthContext } from "../utils/context/AuthContext";

const RequireAuth = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const [loading, setLoading] = useState(true);
  const { user, login } = useContext(AuthContext);
  const { keycloak, initKeycloak } = useKeycloak();

  useEffect(() => {
    const verifyAuth = async () => {
      const accessToken = localStorage.getItem("accessToken");
      const refreshToken = localStorage.getItem("refreshToken");
      const userData = JSON.parse(localStorage.getItem("userData") || "{}");
      const keycloakName = sessionStorage.getItem("keycloakName");
      const clientId = userData?.keycloakClientId;
      const email = sessionStorage.getItem("email");

      sessionStorage.setItem("requestedPath", location.pathname);

      if (!user && (!accessToken || !refreshToken || !userData?.userId)) {
        Swal.fire({
          title: "Session Expired",
          text: "Please login again",
          icon: "warning",
          confirmButtonText: "OK",
        }).then(() => {
          localStorage.clear();
          sessionStorage.clear();
          navigate("/");
        });
        return;
      }

      if (!keycloak && clientId) {
        const newKeycloak = await initKeycloak(keycloakName, clientId, email);
        if (!newKeycloak) {
          Swal.fire({
            title: "Session Expired",
            text: "Please login again",
            icon: "warning",
            confirmButtonText: "OK",
          }).then(() => {
            localStorage.clear();
            sessionStorage.clear();
            navigate("/");
          });
          return;
        }
      }

      if (keycloak) {
        try {
          const refreshed = await keycloak.updateToken(5);
          if (refreshed) {
            const updatedUserData = {
              ...userData,
              accessToken: keycloak.token,
              refreshToken: keycloak.refreshToken,
            };
            localStorage.setItem("accessToken", keycloak.token);
            localStorage.setItem("refreshToken", keycloak.refreshToken);
            localStorage.setItem("userData", JSON.stringify(updatedUserData));
            login(updatedUserData);
          }
        } catch (err) {
          console.error("Token refresh error:", err);
          Swal.fire({
            title: "Session Expired",
            text: "Please login again",
            icon: "warning",
            confirmButtonText: "OK",
          }).then(() => {
            localStorage.clear();
            sessionStorage.clear();
            navigate("/");
          });
          return;
        }
      }

      setLoading(false);
    };

    verifyAuth();

    const handleAuthChange = () => {
      verifyAuth();
    };

    window.addEventListener("authChange", handleAuthChange);
    return () => window.removeEventListener("authChange", handleAuthChange);
  }, [navigate, user, login, keycloak, initKeycloak, location]);

  if (loading) return null;

  return <Outlet />;
};

export default RequireAuth;
```

### ProtectedRoute.jsx

This component enforces role-based access control and refreshes tokens for protected routes.

**Purpose**: Ensures users have valid sessions and required permissions to access specific routes, refreshing tokens and updating user data as needed.

**Key Features**:

- Checks for valid `userData` in `localStorage` and redirects to login if missing.
- Refreshes expired access tokens using `refreshAccessToken` utility.
- Fetches updated user data via `fetchUserById` API and checks for changes in permissions or modules.
- Displays alerts for session expiration, unauthorized access, or permission changes using `sweetalert2`.
- Verifies permissions using `hasPermission` utility for core or module-specific routes.

**Code**:

```jsx
import { useEffect } from "react";
import { useNavigate } from "react-router-dom";
import Swal from "sweetalert2";
import apiMethods from "./apiMethods";
import { isTokenExpired, refreshAccessToken } from "./authUtils";
import hasPermission from "./permissions";
import getConstant from "./constant";

const checkAndUpdateUserSession = async (navigate) => {
  const userData = JSON.parse(localStorage.getItem("userData") || {});
  if (!userData?.userId) {
    navigate("/", { replace: true });
    return false;
  }

  let accessToken = localStorage.getItem("accessToken");
  const refreshToken = localStorage.getItem("refreshToken");

  if (isTokenExpired(accessToken)) {
    if (!refreshToken || isTokenExpired(refreshToken)) {
      Swal.fire({
        title: "Session Expired",
        text: "Please log in again.",
        icon: "warning",
        confirmButtonText: "OK",
      }).then(() => {
        localStorage.clear();
        navigate("/", { replace: true });
      });
      return false;
    }

    const tokenData = await refreshAccessToken();
    if (!tokenData) {
      Swal.fire({
        title: "Session Expired",
        text: "Please log in again.",
        icon: "warning",
        confirmButtonText: "OK",
      }).then(() => {
        localStorage.clear();
        navigate("/", { replace: true });
      });
      return false;
    }

    accessToken = tokenData.accessToken;
    localStorage.setItem("accessToken", accessToken);
    localStorage.setItem(
      "userData",
      JSON.stringify({
        ...userData,
        loggedInUserPermissions: tokenData.loggedInUserPermissions || [],
        userModulePermissions: tokenData.userModulePermissions || [],
      })
    );
  }

  try {
    const response = await apiMethods.fetchUserById(userData.userId);
    const fetchedUser = response.data.user;
    const updatedLoggedInUserPermissions =
      response.data.loggedInUserPermissions || [];
    const updatedUserModulePermissions =
      response.data.userModulePermissions || [];
    const updatedModules = fetchedUser.modules || [];

    const storedLoggedInUserPermissions =
      userData.loggedInUserPermissions || [];
    const storedUserModulePermissions = userData.userModulePermissions || [];
    const storedModules = userData.modules || [];

    const coreChanged =
      JSON.stringify(storedLoggedInUserPermissions) !==
      JSON.stringify(updatedLoggedInUserPermissions);
    const moduleChanged =
      JSON.stringify(storedUserModulePermissions) !==
      JSON.stringify(updatedUserModulePermissions);
    const modulesChanged =
      JSON.stringify(storedModules) !== JSON.stringify(updatedModules);

    if (coreChanged || moduleChanged || modulesChanged) {
      Swal.fire({
        title: "Changes Detected",
        text: "Your permissions have changed. Please reload or re-login.",
        icon: "warning",
        showCancelButton: true,
        confirmButtonText: "Re-login",
        cancelButtonText: "Reload",
      }).then((result) => {
        if (result.isConfirmed) {
          localStorage.clear();
          navigate("/", { replace: true });
        } else {
          window.location.reload();
        }
      });
      return false;
    }

    localStorage.setItem(
      "userData",
      JSON.stringify({
        ...userData,
        loggedInUserPermissions: updatedLoggedInUserPermissions,
        userModulePermissions: updatedUserModulePermissions,
        modules: updatedModules,
      })
    );

    return true;
  } catch (error) {
    console.error("User fetch failed:", error);
    Swal.fire({
      title: "Error",
      text: "Something went wrong. Please login again.",
      icon: "error",
    }).then(() => {
      localStorage.clear();
      navigate("/", { replace: true });
    });
    return false;
  }
};

const ProtectedRoute = ({ children, requiredPermission, moduleName }) => {
  const navigate = useNavigate();

  const showSessionExpiredAlert = () => {
    Swal.fire({
      title: "Session Expired",
      text: "Your session has expired. Please log in again!",
      icon: "warning",
      confirmButtonText: "OK",
      allowOutsideClick: false,
    }).then(() => {
      localStorage.clear();
      navigate("/");
    });
  };

  const showUnauthorizedAlert = () => {
    Swal.fire({
      title: "Access Denied",
      text: "You do not have permission to access this page.",
      icon: "error",
      confirmButtonText: "OK",
      confirmButtonColor: "#dc3545",
    }).then(() => {
      navigate("/unauthorized", { replace: true });
    });
  };

  const showChangesDetectedAlert = () => {
    Swal.fire({
      title: "Changes Detected",
      text: "Your account details or permissions have been updated. Please reload or log in again to apply the changes.",
      icon: "warning",
      confirmButtonText: "Re-login",
      cancelButtonText: "Reload",
      showCancelButton: true,
      confirmButtonColor: "#28a745",
      cancelButtonColor: "#007bff",
    }).then((result) => {
      if (result.isConfirmed) {
        localStorage.clear();
        navigate("/", { replace: true });
      } else {
        window.location.reload();
      }
    });
  };

  useEffect(() => {
    const validateAndProceed = async () => {
      const isValid = await checkAndUpdateUserSession(navigate);
      if (!isValid) return;

      const userData = JSON.parse(localStorage.getItem("userData"));
      const CONSTANT = getConstant();
      const isCoreModule =
        moduleName && CONSTANT.CORE_MODULES.includes(moduleName.toLowerCase());
      const relevantPermissions = isCoreModule
        ? userData.loggedInUserPermissions
        : userData.userModulePermissions;

      if (
        requiredPermission &&
        !hasPermission(relevantPermissions, requiredPermission, moduleName)
      ) {
        Swal.fire({
          title: "Access Denied",
          text: "You do not have permission to access this page.",
          icon: "error",
          confirmButtonText: "OK",
          confirmButtonColor: "#dc3545",
        }).then(() => {
          navigate("/unauthorized", { replace: true });
        });
      }
    };

    validateAndProceed();

    const handleAuthChange = () => validateAndProceed();
    window.addEventListener("authChange", handleAuthChange);
    return () => window.removeEventListener("authChange", handleAuthChange);
  }, [navigate, requiredPermission, moduleName]);

  return children;
};

export default ProtectedRoute;
```

## Authentication Flow

1. **User Input**: The user enters their email or username in the `ClientIdForm` component.
2. **Client ID and Realm Retrieval**: The form submits the input to the backend API (`/users/get-keycloak-client-id`) to fetch a dynamic client ID and realm name.
3. **Keycloak Initialization**: The `KeycloakProvider` initializes the Keycloak instance using the fetched client ID, realm name, and user input as `loginHint`.
4. **Keycloak Authentication**: Keycloak redirects to its login page (if not authenticated) and, upon successful login, redirects back to the `/auth/callback` route.
5. **Callback Handling**: The `AuthCallback` component processes the authentication response, stores tokens in `localStorage`, fetches user data from the backend (`/auth/login`), and updates the `AuthContext`.
6. **Token Refresh and Route Protection**: The `RequireAuth` component verifies authentication and refreshes tokens if needed, while `ProtectedRoute` checks permissions and updates user data, redirecting to `/unauthorized` or login if necessary.
7. **Redirect**: The user is redirected to the dashboard or the originally requested path stored in `sessionStorage`.
8. **Logout**: The `logout` function in `KeycloakProvider` clears storage and redirects to the home page.

## Setup and Configuration

1. **Install Dependencies**:

   - Install `keycloak-js` for Keycloak integration:
     ```bash
     npm install keycloak-js
     ```
   - Install `react-router-dom` for navigation:
     ```bash
     npm install react-router-dom
     ```
   - Install `sweetalert2` for user alerts:
     ```bash
     npm install sweetalert2
     ```

2. **Keycloak Configuration**:

   - Keycloak server URL: `your_server_url`
   - Realm: Dynamic, fetched via API (`keycloakName`)
   - Redirect URI: `window.location.origin + '/auth/callback'`
   - Ensure the Keycloak server is configured with the correct client ID and redirect URI.

3. **Backend APIs**:

   - `/users/get-keycloak-client-id`: Expects a POST request with an `identifier` (email or username) and returns a client ID and realm name.
   - `/auth/login`: Expects a POST request and returns user data (userId, username, email, role, permissions, etc.).
   - `fetchUserById`: Fetches updated user data for permission and module checks.

4. **Routing**:

   - Configure React Router with routes for `/` (`ClientIdForm`), `/auth/callback` (`AuthCallback`), and protected routes wrapped in `RequireAuth` and `ProtectedRoute`.

## Usage

1. **Login**:

   - Navigate to the root route (`/`) to access the `ClientIdForm`.
   - Enter a valid email or username and submit the form.
   - After successful Keycloak authentication, the user is redirected to the dashboard or the requested path.

2. **Accessing Protected Routes**:

   - Use `RequireAuth` to wrap routes that require authentication.
   - Use `ProtectedRoute` to enforce specific permissions for routes, passing `requiredPermission` and `moduleName` props as needed.

3. **Logout**:

   - Call the `logout` function from `useKeycloak` to log out the user, clear storage, and redirect to the home page.

4. **Accessing Keycloak**:

   - Use the `useKeycloak` hook in any component to access the Keycloak instance, `initKeycloak`, and `logout` functions.

## Error Handling

- **ClientIdForm**:
  - Validates input for empty fields or invalid email/username format.
  - Displays toast notifications for errors (e.g., "Client ID not found").
- **AuthCallback**:
  - Checks for missing `email`, `keycloakName`, or `clientId` in `sessionStorage`.
  - Handles missing Keycloak tokens or API errors with appropriate toast notifications.
- **RequireAuth**:
  - Redirects to login if tokens or user data are missing or invalid.
  - Handles token refresh failures with `sweetalert2` alerts.
- **ProtectedRoute**:
  - Displays alerts for session expiration, unauthorized access, or permission changes.
  - Updates user data and checks for changes to prevent inconsistent states.
- **KeycloakProvider**:
  - Returns `null` if Keycloak initialization fails.

## Dependencies

- **React**: For building the UI.
- **react-router-dom**: For navigation and routing.
- **Custom Utilities**:
  - `apiMethods`: Handles API requests (`postData`, `fetchUserById`).
  - `showToast`: Displays toast notifications.
  - `AuthContext`: Manages user authentication state.
  - `authUtils`: Provides token expiration and refresh functions.
  - `permissions`: Checks user permissions for routes.
  - `constant`: Provides constants like `CORE_MODULES`.
  - UI components (`TextBox`, `Button`, `Loader`).

## Security Considerations

- **Token Storage**: Tokens are stored in `localStorage`, which is vulnerable to XSS attacks. Consider using `sessionStorage` or a more secure storage mechanism for production.
- **Session Management**: The `logout` function clears both `sessionStorage` and `localStorage` to prevent session leaks.
- **Token Refresh**: `RequireAuth` and `ProtectedRoute` handle token refresh to maintain session validity.
- **Input Validation**: The `ClientIdForm` validates user input to prevent invalid submissions.
- **Keycloak Configuration**: Ensure the Keycloak server is properly configured with secure redirect URIs and client settings.
- **HTTPS**: Use HTTPS in production to secure API calls and Keycloak communication.

## Troubleshooting

- **Keycloak Initialization Fails**:
  - Verify the Keycloak server URL, realm name, and client ID are correct.
  - Ensure the client ID and realm are correctly fetched from the API.
- **Callback Errors**:
  - Check if `email`, `keycloakName`, and `clientId` are correctly stored in `sessionStorage`.
  - Ensure the `/auth/login` API returns the expected user data.
- **Navigation Issues**:
  - Verify React Router is properly configured with `RequireAuth` and `ProtectedRoute`.
  - Check that the `requestedPath` in `sessionStorage` is correctly set and cleared.
- **Permission Errors**:
  - Ensure the `hasPermission` utility correctly evaluates permissions.
  - Verify that `fetchUserById` returns updated permissions and modules.
- **Toast and Alert Notifications**:
  - Ensure `showToast` and `sweetalert2` are correctly implemented to display errors.

This documentation provides a clear and detailed guide to the Keycloak authentication implementation, ensuring developers can understand, maintain, and extend the system effectively.
