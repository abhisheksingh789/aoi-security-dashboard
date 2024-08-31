import React from 'react';
import { Card, CardContent, Typography, Box, Button } from '@mui/material';
import { Link } from 'react-router-dom';

function APICard({ path, method }) {
  return (
    <Card 
      sx={{ 
        width: 300,
        height: 200,
        margin: 'auto',
        background: 'linear-gradient(135deg, #2b2b44, #2e2e5b)',
        borderRadius: '15px',
        boxShadow: '0 8px 16px rgba(0, 0, 0, 0.3)',
        color: '#ffffff',
      }}
    >
      <CardContent style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between', height: '100%' }}>
  <div>
    <Typography gutterBottom variant="h6" component="div" sx={{ fontWeight: 'bold' }}>
      Path: {path}
    </Typography>
    <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: '1rem' }}>
      <Typography variant="body2" color="textSecondary" sx={{ fontWeight: 'bold', color: '#c0c0ff' }}>
        Method: {method}
      </Typography>
    </Box>
  </div>
  <Button 
    variant="contained" 
    color="primary" 
    component={Link} 
    to={`/api-details/${path.replace('/', '')}`} 
    sx={{ 
      marginTop: 'auto', 
      marginBottom: '0.25rem',
      backgroundColor: '#c101fb',
      '&:hover': {
        backgroundColor: '#b300e6',
        color: '#ffffff',
      },
    }}
  >
    View Details
  </Button>
</CardContent>
    </Card>
  );
}

export default APICard;
