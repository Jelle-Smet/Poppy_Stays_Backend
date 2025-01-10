# Poppy Stays Backend

# Welcome to the backend of the Poppy Stays project!
This backend is built using **Node.js** with **Express.js** to handle the API endpoints and manage the server-side logic for the application.

# Overview
Poppy Stays is a platform designed to connect travelers with unique camping spots and BnBs. The backend provides the following functionalities:

- User Authentication: Login and registration of users.
- Booking System: Manage bookings for camping spots.
- Spot Management: Create, update, and manage camping spot details.
- Promotions: Manage promotional offers for users.
- Notifications: Send notifications related to bookings and updates.
- Categories and Amenities: Organize spots by categories and amenities.

All the logic for these features is implemented in the `express.js` file.

# Requirements
Before you begin, make sure you have the following installed:

- **Node.js** (v16 or higher)
- **npm** (Node Package Manager)

# Setup
To get started with the backend:

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd backend
   ```

2. Install the dependencies:
   ```bash
   npm install
   ```

3. Start the server:
   ```bash
   node express.js
   ```

   The server will start on the default port (e.g., `http://localhost:3000`).

4. (Optional) Use `nodemon` for automatic restarts during development:
   ```bash
   npx nodemon express.js
   ```

# API Endpoints
All the endpoints are defined in the `express.js` file. These endpoints handle requests for user authentication, booking management, spot updates, promotions, and more.

## Example Endpoints
Here are a few examples of the API endpoints:

- **User Login:**
  ```
  POST /api/login
  ```
  Authenticate users and return a token.

- **Spot Update:**
  ```
  PUT /api/update-spot/:spotId
  ```
  Update details of a specific camping spot.

- **Promotions:**
  ```
  GET /api/promotions
  ```
  Retrieve all active promotions.

- **Booking Confirmation:**
  ```
  POST /api/confirm-booking
  ```
  Confirm a user’s booking for a camping spot.

# Notes
- All database logic is handled in a separate `database.js` file located in the `classes` folder.
- The project uses a simple file structure for now, and all logic is in `express.js`. This may be refactored in the future.

# Contributing
If you’d like to contribute:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Submit a pull request once your changes are complete.

# License
This project is licensed under the MIT License. See the `LICENSE` file for more details.

---

Thank you for using Poppy Stays! If you have any questions, feel free to reach out.

