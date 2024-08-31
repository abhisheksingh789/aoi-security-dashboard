import React from 'react';
import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import Home from './components/Home';
import APIList from './components/APIList';
import Vulnerabilities from './components/Vulnerabilities';
import APIDetails from './components/APIDetails';
import Dashboard from './components/Dashboard';
import Login from './components/Login';
import AboutUs from './components/AboutUs';

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/login" element={<Login />} />
        <Route path="/about" element={<AboutUs />} />
        <Route path="/apis" element={<APIList />} />
        <Route path="/vulnerabilities" element={<Vulnerabilities />} />
        <Route path="/api-details/:path" element={<APIDetails />} />
        <Route path="/dashboard" element={<Dashboard />} />
      </Routes>
    </Router>
  );
}

export default App;
