import { describe, expect, it } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import App from './App';

describe('App', () => {
  it('renders the analyst alert queue and review controls', () => {
    render(<App />);
    expect(screen.getByRole('heading', { name: 'Alert queue' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Approve recommendation' })).toBeTruthy();
  });

  it('switches sidebar workspaces and sorts the queue', () => {
    render(<App />);
    fireEvent.click(screen.getAllByRole('button', { name: /Incidents/ })[0]);
    expect(screen.getAllByRole('heading', { name: 'Incidents' }).length).toBeGreaterThan(0);
    fireEvent.click(screen.getByRole('button', { name: /Open alert queue/ }));
    expect(screen.getAllByRole('heading', { name: 'Alert queue' }).length).toBeGreaterThan(0);
    screen.getAllByRole('combobox', { name: 'Sort alerts' })[0];
    expect(screen.getAllByRole('option', { name: 'Confidence' }).length).toBeGreaterThan(0);
  });
});
