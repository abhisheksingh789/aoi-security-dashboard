import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { Box, Container, Typography, Paper, Grid } from '@mui/material';
import { useNavigate, useParams } from 'react-router-dom';
import LoadingComponent from './Loading';
import BASE_URL from './baseURL';

function APIDetails() {
  const { path } = useParams();
  const [details, setDetails] = useState({});
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (!token) {
      navigate('/login');
    }
    axios.get(`${BASE_URL}/api/vulnerabilities/${path}`)
      .then(response => {
        setDetails(response.data);
        setLoading(false);
      })
      .catch(error => {
        console.error('Error fetching API details:', error);
        setDetails({});
        setLoading(false);
      });
  }, [path]);

  const getSolutionText = (vulnerabilityName) => {
    const solutions = {
      "SQL Injection": [
        "Use parameterized queries or prepared statements.",
        "Employ ORM frameworks to avoid direct SQL queries.",
        "Sanitize and validate all user inputs.",
        "Implement least privilege access control for databases.",
        "Regularly update and patch database management systems."
      ],
      "SSRF": [
        "Validate and sanitize all URLs.",
        "Use a whitelist for allowed domains.",
        "Avoid user input in sensitive internal requests.",
        "Implement network segmentation to limit internal access.",
        "Use firewalls to block unauthorized outbound requests."
      ],
      "Unsafe API Usage": [
        "Validate and sanitize all URLs.",
        "Check API responses for errors and handle them appropriately.",
        "Implement proper authentication and authorization.",
        "Use HTTPS for all communications.",
        "Limit API exposure and use rate limiting."
      ],
      "Security Misconfiguration": [
        "Disable unused features and services.",
        "Regularly update and patch systems.",
        "Implement least privilege access control.",
        "Use security tools to detect misconfigurations.",
        "Ensure proper security headers are in place."
      ],
      "Broken Authentication": [
        "Implement multi-factor authentication (MFA).",
        "Use secure password storage (e.g., bcrypt).",
        "Enforce strong password policies.",
        "Monitor and limit login attempts.",
        "Secure session management."
      ],
      "Broken Object Level Authorization": [
        "Implement proper object-level access controls.",
        "Validate and enforce ownership on every request.",
        "Use unique and unpredictable identifiers for objects.",
        "Test APIs for access control vulnerabilities.",
        "Use an access control matrix."
      ],
      "Broken Function Level Authorization": [
        "Enforce role-based access control.",
        "Deny by default, allow by exception.",
        "Review and test for function-level authorization.",
        "Segregate administrative functions.",
        "Use least privilege principle."
      ],
      "Broken Object Property Level Authorization": [
        "Validate permissions on every object property access.",
        "Enforce role-based access control for properties.",
        "Use object property validation libraries.",
        "Regularly audit object properties.",
        "Implement secure coding practices."
      ],
      "Unrestricted Business Flow": [
        "Implement proper state management and validation.",
        "Use transaction-based security.",
        "Implement rate limiting and quotas.",
        "Validate all business logic inputs.",
        "Monitor for abnormal business logic usage."
      ],
      "Unrestricted Resource Consumption": [
        "Implement resource quotas and limits.",
        "Use rate limiting for resource-intensive operations.",
        "Monitor and alert on resource usage.",
        "Implement backpressure in services.",
        "Optimize resource-heavy operations."
      ],
      "Improper Inventory Management": [
        "Implement strict API versioning and deprecation policies.",
        "Regularly audit API endpoints.",
        "Limit API exposure to only required endpoints.",
        "Implement proper access controls for API inventory.",
        "Use automated tools to manage and monitor API inventories."
      ],
    };
    return solutions[vulnerabilityName] || ["No specific solution available."];
  };

  if (loading) {
    return <LoadingComponent />
  }

  return (
    <Box
      sx={{
        backgroundImage: 'url(/all_background.png)',
        backgroundSize: 'cover',
        backgroundPosition: 'center',
        backgroundAttachment: 'fixed',
        minHeight: '100vh',
        minWidth: '100vw',
        color: '#ffffff',
        overflowX: 'hidden',
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        flexDirection: 'column',
      }}
    >
      <Container 
        maxWidth="lg" 
        sx={{ 
          position: 'relative', 
          zIndex: 2,
          paddingTop: '0', 
          marginTop: '2rem'
        }}
      >
        <Typography 
          variant="h4" 
          align="center" 
          gutterBottom 
          sx={{ 
            marginBottom: '1rem', 
            marginTop: '0', 
            color: '#fff' 
          }}
        >
          API Details for {path}
        </Typography>

        <Grid container spacing={4}>
          <Grid item xs={12}>
            {Object.entries(details).map(([key, vulnerabilities], index) => (
              vulnerabilities.length > 0 && (
                <Paper
                  elevation={4}
                  key={index}
                  sx={{
                    backgroundColor: 'rgba(33, 33, 62, 0.9)',
                    backdropFilter: 'blur(10px)',
                    borderRadius: '12px',
                    padding: '2rem',
                    boxShadow: '0px 4px 15px rgba(0, 0, 0, 0.3)',
                    marginBottom: '2rem',
                  }}
                >
                  <Grid container spacing={2}>
                    <Grid item xs={12} md={4}>
                      <Box
                        sx={{
                          display: 'flex',
                          justifyContent: 'center',
                          alignItems: 'center',
                          height: '100%',
                        }}
                      >
                        <img
                          src={`/${key}.png`}
                          alt={`${key} vulnerability`}
                          style={{ width: '350px', height: '250px', objectFit: 'cover', borderRadius: '8px' }}
                        />
                      </Box>
                    </Grid>
                    <Grid item xs={12} md={8}>
                      <Typography 
                        variant="h5" 
                        sx={{ 
                          marginBottom: '1rem',
                          fontWeight: 'bold',
                          color: '#c101fb',
                          textShadow: '1px 1px 3px rgba(0, 0, 0, 0.3)',
                        }}
                      >
                        {key === "SSRF" ? "Server-Side Request Forgery (SSRF)" : key}
                      </Typography>
                      {getSolutionText(key).map((solution, idx) => (
                        <Typography 
                          key={idx}
                          variant="body2"  // Smaller font size
                          sx={{ 
                            color: '#ffffff', 
                            padding: '0.5rem 1rem',
                            backgroundColor: 'rgba(0, 0, 0, 0.5)',
                            borderRadius: '8px',
                            textAlign: 'left',
                            marginBottom: '0.5rem', // Space between points
                          }}
                        >
                          {solution}
                        </Typography>
                      ))}
                    </Grid>
                  </Grid>
                </Paper>
              )
            ))}
          </Grid>
        </Grid>
      </Container>
    </Box>
  );
}

export default APIDetails;
