import React from 'react';
import { Box, Typography, Container, Paper } from '@mui/material';

function AboutUs() {
  return (
    <Box
      sx={{
        backgroundImage: 'url(/all_background.png)',
        backgroundSize: 'cover',
        backgroundPosition: 'center',
        backgroundRepeat: 'no-repeat',
        height: '100vh',
        width: '100vw',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
      }}
    >
      <Container component="main" maxWidth="md" sx={{ mt: 4, mb: 4, backgroundColor: 'transparent' }}>
        <Paper elevation={6} sx={{ p: 4, backgroundColor: 'rgba(33, 33, 62, 0.9)', color: '#fff' }}>
          <Typography variant="h3" component="h1" gutterBottom sx={{ fontWeight: 'bold', color: '#c101fb' }}>
            About API Security Shield
          </Typography>
          <Typography variant="h5" component="h2" gutterBottom sx={{ mt: 2 }}>
            What We Do
          </Typography>
          <Typography paragraph sx={{ fontSize: '1.1rem' }}>
            API Security Shield is a comprehensive security solution designed to protect and manage API infrastructures. We provide real-time analytics, vulnerability assessment, and security enforcement to safeguard your APIs from potential threats.
          </Typography>
          <Typography variant="h5" component="h2" gutterBottom sx={{ mt: 2 }}>
            Our Mission
          </Typography>
          <Typography paragraph sx={{ fontSize: '1.1rem' }}>
            Our mission is to enhance the security posture of organizations by providing a robust and intuitive platform to detect, report, and mitigate API vulnerabilities effectively. We aim to empower businesses to uphold the integrity and confidentiality of their data exchanges.
          </Typography>
          <Typography variant="h5" component="h2" gutterBottom sx={{ mt: 2 }}>
            Get In Touch
          </Typography>
          <Typography paragraph sx={{ fontSize: '1.1rem' }}>
            If you have any questions or require further information about how our dashboard can protect your digital assets, feel free to reach out.
          </Typography>
          <Typography paragraph>
            <strong>Email:</strong> support@api-security-shield.com
          </Typography>
          <Typography paragraph>
            <strong>Phone:</strong> (123) 456-7890
          </Typography>
        </Paper>
      </Container>
    </Box>
  );
}

export default AboutUs;
